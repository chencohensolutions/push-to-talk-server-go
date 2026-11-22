package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/extension"
	"github.com/99designs/gqlgen/graphql/handler/lru"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/contacts"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/generated"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/model"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/resolver"
	"github.com/chencohensolutions/push-to-talk-server-go/invite"
	"github.com/chencohensolutions/push-to-talk-server-go/push"
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
}

// serve runs the server until ctx ends, Ctrl+C or a stop from the system, then calls stopped once the router's
// port mapping is removed.
func serve(ctx context.Context, config auth.AppConfig, stopped func()) {
	log.Printf("ptt-server %s", version.String())
	for _, key := range config.UnusedKeys() {
		log.Printf("config.json: %q is no longer used (the inviter's phone sends invites; the server sends no mail): remove it", key)
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
	go serveAdmin(s)
	go func() {
		<-running.Done()
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
	st, err := store.Open(config.DatabaseFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open the database: %w", err)
	}
	queueTTL := time.Duration(config.QueueDays) * 24 * time.Hour
	s := &server{config: config, users: users, enrollment: enrollment, book: book, store: st,
		relay: relay.New(users, enrollment.Registry, st, book, queueTTL, time.Now)}
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
	return mux
}

func (s *server) newGraphQLServer() *handler.Server {
	srv := handler.New(generated.NewExecutableSchema(generated.Config{
		Resolvers: &resolver.Resolver{Enrollment: s.enrollment, Users: s.users, Relay: s.relay, Invites: s.invites, Now: time.Now,
			Version: version.String(),
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
