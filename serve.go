package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/chencohensolutions/push-to-talk-server-go/apprelease"
	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/chencohensolutions/push-to-talk-server-go/contacts"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/generated"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/model"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/resolver"
	"github.com/chencohensolutions/push-to-talk-server-go/groups"
	"github.com/chencohensolutions/push-to-talk-server-go/invite"
	"github.com/chencohensolutions/push-to-talk-server-go/livekit"
	"github.com/chencohensolutions/push-to-talk-server-go/mail"
	"github.com/chencohensolutions/push-to-talk-server-go/push"
	"github.com/chencohensolutions/push-to-talk-server-go/recorder"
	"github.com/chencohensolutions/push-to-talk-server-go/relay"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
	"github.com/chencohensolutions/push-to-talk-server-go/version"
	"github.com/vektah/gqlparser/v2/ast"
)

// GraphQL requests are small and quick.
const (
	queryReadTimeout  = 30 * time.Second
	queryWriteTimeout = 2 * time.Minute
)

// server is what the running server is made of, shared by the routes, the admin API and the tests.
type server struct {
	config     auth.AppConfig
	users      *auth.Users
	enrollment *enroll.Service
	// Pairs and blocks (pairs.json), the database (prekeys, the queue) and the routing over /ws.
	book  *contacts.Book
	store *store.Store
	relay *relay.Relay
	// Invites (invites.json, the wrong passcodes); nil when config.json turns them off.
	invites *invite.Service
	// Who this server is and where, for serverInfo.discovery; nil when unknown.
	discovery func() *model.ServerDiscovery
	// LiveKit's keys (talkToken) and its signalling, which /rtc passes to; nil without LiveKit.
	liveKeys *livekit.Keys
	rtc      http.Handler
	// Saves calls (recordCall); nil without LiveKit.
	recorder *recorder.Recorder
	// The talk buffer's recorder; nil without LiveKit.
	talkBuffers *recorder.TalkBuffers
	// Follows the app's releases and pushes app_update to the phones; nil when app_releases is "none".
	appReleases *apprelease.Watcher
	// Sends the enrollment links (config.json "gmail"); nil when the server sends no mail or can't.
	mail mail.Sender
	// liveRestart restarts the livekit-server this server runs (restartLiveKit); nil when it runs none.
	liveRestart chan struct{}
}

// removedUser drops what a removed user left besides its devices: its pending invites, so a user added again by the
// same name doesn't find them counted against it (2026-11-22: hen, re-added, couldn't invite).
func (s *server) removedUser(user string) {
	if s.invites == nil {
		return
	}
	if n, err := s.invites.Store.CancelAll(user); err != nil {
		log.Printf("User %s removed, but its invites couldn't be canceled: %v", user, err)
	} else if n > 0 {
		log.Printf("User %s removed: canceled its %d pending invites", user, n)
	}
}

// restartLiveKit asks livekit.Run to start LiveKit again, and says whether this server runs it.
func (s *server) restartLiveKit() bool {
	if s.liveRestart == nil {
		return false
	}
	select {
	case s.liveRestart <- struct{}{}:
	default: // one is asked already
	}
	return true
}

// serve runs the server until ctx ends, Ctrl+C or a stop from the system, then calls stopped once the router's
// port mapping is removed.
func serve(ctx context.Context, config auth.AppConfig, stopped func()) {
	log.Printf("ptt-server %s", version.String())
	for _, key := range config.UnusedKeys() {
		log.Printf("config.json: %q is no longer used (the server mails only enrollment links, through \"gmail\"): remove it", key)
	}
	tlsConfig, err := createTLSConfig(config)
	if err != nil {
		log.Fatalf("failed to create TLS config: %v", err)
	}
	s, err := openServer(config)
	if err != nil {
		log.Fatal(err)
	}
	running, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	unmapped := make(chan struct{}) // the router's port mapping is removed on stop, before the process ends
	if d, err := openDiscovery(config); err != nil {
		log.Printf("Discovery is off: %v", err)
		close(unmapped)
	} else {
		s.discovery = d.forPhones
		mapPorts(running, config, d, unmapped)
		go d.publisher.Run(running)
	}
	go s.relay.Run(running)
	if s.appReleases != nil {
		log.Printf("App releases: followed hourly at github.com/%s; phones are pushed app_update for a new one", config.AppReleases)
		go s.appReleases.Run(running)
	}
	if binary := liveKitBinary(config); binary != "" {
		s.liveRestart = make(chan struct{}, 1)
		go livekit.Run(running, binary, config.LiveKit.ConfigFile, *s.liveKeys, s.liveRestart)
	}
	go serveAdmin(s)
	go func() {
		<-running.Done()
		if s.recorder != nil {
			s.recorder.StopAll() // the saved calls' tracks are completed
		}
		if s.talkBuffers != nil {
			s.talkBuffers.StopAll()
		}
		stop() // a second Ctrl+C now ends the process the usual way
		log.Printf("Stopping: removing the port mapping (Ctrl+C again to stop now)")
		select {
		case <-unmapped:
		case <-time.After(10 * time.Second):
		}
		s.store.Close() // writes SQLite's log back into ptt.db
		log.Printf("Stopped")
		stopped()
	}()

	httpServer := &http.Server{
		Addr:              ":" + config.Port,
		Handler:           s.newMux(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	ln, err := net.Listen("tcp", httpServer.Addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("Listening on https://0.0.0.0:%s", config.Port)
	log.Fatal(httpServer.Serve(tls.NewListener(&loggingListener{Listener: ln}, tlsConfig)))
}

// openServer loads the users, the client CA's key (which signs enrolled devices) and the device registry.
func openServer(config auth.AppConfig) (*server, error) {
	users, err := auth.OpenUsers(config.UsersFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open the users: %w", err)
	}
	enrollment, err := openEnrollment(config)
	if err != nil {
		return nil, err
	}
	enrollment.UserExists = func(name string) bool { return users.Find(name) != nil }
	book, err := contacts.Open(config.PairsFile, time.Now)
	if err != nil {
		return nil, fmt.Errorf("failed to open the pairs: %w", err)
	}
	groupBook, err := groups.Open(config.GroupsFile, time.Now)
	if err != nil {
		return nil, fmt.Errorf("failed to open the groups: %w", err)
	}
	st, err := store.Open(config.DatabaseFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open the database: %w", err)
	}
	queueTTL := time.Duration(config.QueueDays) * 24 * time.Hour
	s := &server{config: config, users: users, enrollment: enrollment, book: book, store: st,
		relay: relay.New(users, enrollment.Registry, st, book, queueTTL, time.Now)}
	s.relay.Groups = groupBook
	blobStore, err := blobs.Open(config.BlobDir, time.Now)
	if err != nil {
		return nil, fmt.Errorf("failed to open the blobs folder: %w", err)
	}
	s.relay.Blobs = blobStore
	s.relay.BlobTTL = time.Duration(config.BlobDays) * 24 * time.Hour
	s.relay.MediaTTL = time.Duration(config.MediaDays) * 24 * time.Hour
	blobStore.MaxFile = config.MaxBlobMB << 20
	blobStore.MinFree = max(config.MinFreeGB, 0) << 30
	if config.LiveKitOn() {
		s.relay.CallTTL = time.Duration(config.LiveKit.KeepCallDays) * 24 * time.Hour
		hours := config.LiveKit.TalkBufferHours
		if hours <= 0 {
			hours = auth.DefaultTalkBufferHours
		}
		s.relay.TalkBufferTTL = time.Duration(hours) * time.Hour
	}
	var sender push.Sender
	if config.PushOn() {
		fcm, err := push.LoadFCM(config.FCM.ServiceAccountFile, config.FCM.ProjectID, config.FCM.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("config.json fcm: %w", err)
		}
		log.Printf("Push: on, through FCM for the Firebase project %s", fcm.Project())
		sender = fcm
	} else {
		log.Printf("Push: off (no fcm in config.json); phones receive only while connected")
	}
	s.relay.Push = push.New(sender, enrollment.Registry, s.relay.Connected)
	if config.LiveKitOn() {
		keys, err := livekit.LoadKeys(config.LiveKit.KeysFile)
		if err != nil {
			return nil, fmt.Errorf("config.json livekit: %w (ptt-server setup makes it)", err)
		}
		target, err := url.Parse(config.LiveKit.URL)
		if err != nil {
			return nil, fmt.Errorf("config.json livekit url: %w", err)
		}
		s.liveKeys = &keys
		if config.LiveKit.KeepsCalls() {
			s.recorder = &recorder.Recorder{Keys: keys, URL: config.LiveKit.URL, Blobs: s.relay.Blobs}
			log.Printf("Calls: kept while someone records them, encrypted end to end, in %s (livekit.keep_calls)", config.BlobDir)
		}
		maxCall := config.LiveKit.MaxCallDevices
		if maxCall <= 0 {
			maxCall = auth.DefaultMaxCallDevices
		}
		s.relay.Live = &livekit.Client{Keys: keys, URL: config.LiveKit.URL, MaxCall: maxCall}
		if s.recorder != nil {
			s.recorder.Changed = recordingShown(s.relay.Live)
		}
		// The talk buffer (2026-11-25, hen): the recorder in each talk room keeps pushes for members not in it.
		s.talkBuffers = &recorder.TalkBuffers{Keys: keys, URL: config.LiveKit.URL, Blobs: s.relay.Blobs, Tell: s.relay.TellBuffered}
		log.Printf("Talk buffer: pushes kept for members away from the talk room, %d h at most", int(s.relay.TalkBufferTTL.Hours()))
		s.rtc = httputil.NewSingleHostReverseProxy(target)
		log.Printf("Live talk: on, through LiveKit at %s (media on UDP %d and TCP %d)", config.LiveKit.URL,
			config.LiveKit.UDPPort, config.LiveKit.TCPPort)
	} else {
		log.Printf("Live talk: off (no livekit in config.json); talk goes by the clip path")
	}
	if config.AppReleasesOn() {
		pusher := s.relay.Push
		s.appReleases, err = apprelease.Open(config.AppReleases, config.AppReleaseFile, func(apprelease.Release) int {
			return pusher.AppUpdate()
		})
		if err != nil {
			return nil, fmt.Errorf("failed to open the app release: %w", err)
		}
	}
	if config.MailOn() {
		gmail, err := mail.NewGmail(*config.Gmail)
		if err != nil {
			// The server still starts, so mail-login can be run beside it; enroll-code says it can't mail.
			log.Printf("Mail: can't send: %v", err)
		} else {
			log.Printf("Mail: enrollment links are mailed from %s, through the Gmail API", gmail.From())
			s.mail = gmail
		}
	} else {
		log.Printf("Mail: off (no gmail in config.json); enroll-code prints the codes")
	}
	if config.InvitesOn() {
		invites, err := invite.Open(config.InvitesFile, time.Now)
		if err != nil {
			return nil, fmt.Errorf("failed to open the invites: %w", err)
		}
		s.invites = invite.NewService(invites, users, enrollment, book, time.Now)
	}
	return s, nil
}

// createTLSConfig loads the server certificate and trusts the client CA for client certificates.
func createTLSConfig(config auth.AppConfig) (*tls.Config, error) {
	caBytes, err := os.ReadFile(config.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("failed to read client CA file: %w", err)
	}
	clientCAPool := x509.NewCertPool()
	if !clientCAPool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("failed to append client CA certificates")
	}
	serverCert, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load server TLS certificate: %w", err)
	}
	return tlsConfigFor(serverCert, clientCAPool), nil
}

// tlsConfigFor is the server's TLS setup, shared with the tests.
func tlsConfigFor(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		// Devices that are enrolling have no certificate yet. A certificate that is sent is still
		// verified against the client CA; identify and auth.RequireUserUnlessPublic decide access.
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  clientCAs,
		MinVersion: tls.VersionTLS12,
		// Offer HTTP/2: a device then keeps one connection, with one mTLS handshake (a signature in its secure
		// hardware). http.Server sets h2 up only when it is named here, since the listener is made from this config.
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// openEnrollment loads the client CA's key (which signs enrolled devices) and the device registry.
func openEnrollment(config auth.AppConfig) (*enroll.Service, error) {
	if config.ClientCAKey == "" {
		return nil, fmt.Errorf("config.json: set client_ca_key to the private key of %s (signs enrolled devices)", config.ClientCA)
	}
	issuer, err := enroll.LoadIssuer(config.ClientCA, config.ClientCAKey, time.Now)
	if err != nil {
		return nil, fmt.Errorf("failed to load client CA for enrollment: %w", err)
	}
	registry, err := enroll.OpenRegistry(config.DevicesFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open device registry: %w", err)
	}
	return enroll.NewService(issuer, registry, time.Now), nil
}

// What one GraphQL request may be: a small body from a client without a certificate (an enrollment and its
// certificate request are a few kilobytes), a larger one from a device, and queryComplexity fields.
const (
	anonymousQueryBytes = 64 << 10
	queryBytes          = 1 << 20
	queryComplexity     = 1000
)

// newMux is the routing table. Every route but the playground goes through identify; only /query lets anonymous
// clients in (for the @public enrollment fields).
func (s *server) newMux() *http.ServeMux {
	mux := http.NewServeMux()
	if s.config.Playground {
		mux.Handle("/", playground.Handler("GraphQL playground", "/query"))
	}
	mux.Handle("/query", withDeadlines(queryReadTimeout, queryWriteTimeout,
		identify(s.config, s.users, s.enrollment.Registry, true, limitBody(anonymousQueryBytes, queryBytes,
			s.newGraphQLServer()))))
	// The WebSocket for envelopes (docs/messaging.md): only enrolled devices, and no deadline, since it stays open.
	mux.Handle("/ws", identify(s.config, s.users, s.enrollment.Registry, false, s.relay))
	mux.Handle("/blob/", identify(s.config, s.users, s.enrollment.Registry, false, http.HandlerFunc(s.relay.ServeBlob)))
	if s.rtc != nil {
		// LiveKit's signalling, for enrolled devices only; the room token says which room.
		rtc := identify(s.config, s.users, s.enrollment.Registry, false, s.rtc)
		mux.Handle("/rtc", rtc)
		mux.Handle("/rtc/", rtc)
	}
	return mux
}

func (s *server) newGraphQLServer() *handler.Server {
	srv := handler.New(generated.NewExecutableSchema(generated.Config{
		Resolvers: &resolver.Resolver{Enrollment: s.enrollment, Users: s.users, Relay: s.relay, Invites: s.invites, Now: time.Now, LiveKeys: s.liveKeys, Recorder: s.recorder, TalkBuffers: s.talkBuffers,
			AppReleases: s.appReleases,
			Version:     version.String(),
			Discovery: func() *model.ServerDiscovery {
				if s.discovery == nil {
					return nil
				}
				return s.discovery()
			}},
		Directives: generated.DirectiveRoot{Public: auth.PassThroughDirective},
	}))
	srv.AddTransport(transport.Options{})
	srv.AddTransport(transport.GET{})
	srv.AddTransport(transport.POST{})
	srv.SetQueryCache(lru.New[*ast.QueryDocument](1000))
	// Introspection is a root field too, so anonymous clients cannot read the schema.
	srv.Use(extension.Introspection{})
	srv.Use(extension.AutomaticPersistedQuery{Cache: lru.New[string](100)})
	// A query's cost is the number of fields it asks for. One past the limit is refused before it runs, so a request
	// can't ask for a field ten thousand times under other names.
	srv.Use(extension.FixedComplexityLimit(queryComplexity))
	srv.AroundRootFields(auth.RequireUserUnlessPublic)
	return srv
}

// liveKitBinary is the livekit-server program ptt-server runs, or "" for none: config.json's livekit binary, or
// livekit-server(.exe) beside ptt-server when it is there.
func liveKitBinary(config auth.AppConfig) string {
	if !config.LiveKitOn() || config.LiveKit.Binary == "none" {
		return ""
	}
	if config.LiveKit.Binary != "" {
		return config.LiveKit.Binary
	}
	name := "livekit-server"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if exe, err := os.Executable(); err == nil {
		beside := filepath.Join(filepath.Dir(exe), name)
		if _, err := os.Stat(beside); err == nil {
			return beside
		}
	}
	log.Printf("Live talk: no %s beside ptt-server; start LiveKit yourself, or set livekit.binary in config.json", name)
	return ""
}

// recordingShown puts a call's recording in its room's metadata, which LiveKit sends to every phone in the call, so
// each one shows it (2026-11-22, hen: never kept without everyone in the call seeing it).
func recordingShown(live *livekit.Client) func(room string, st recorder.Status) {
	return func(room string, st recorder.Status) {
		meta := map[string]any{"recording": st.Recording}
		if st.Recording {
			meta["by"] = st.By
			meta["startedAt"] = st.Started.UTC().Format(time.RFC3339)
		}
		data, _ := json.Marshal(meta)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := live.SetRoomMetadata(ctx, room, string(data)); err != nil {
			log.Printf("Recorder: telling room %s: %v", room, err)
		}
	}
}
