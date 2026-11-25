package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
	"github.com/coder/websocket"
)

// fakeFCM is Google's token endpoint and FCM's HTTP v1 API in a test: it checks the service account's signed JWT
// and the bearer token, and keeps the messages it was sent.
type fakeFCM struct {
	*httptest.Server
	key      *rsa.PrivateKey
	messages chan fcmMessage
	mu       sync.Mutex
	// The answers to give for a token instead of 200: status and FCM's errorCode.
	answers map[string][2]string
	logins  int
}

type fcmMessage struct {
	Token   string
	Data    map[string]string
	Android struct {
		Priority    string `json:"priority"`
		TTL         string `json:"ttl"`
		CollapseKey string `json:"collapse_key"`
	}
}

const fakeAccessToken = "fake-access-token"

func newFakeFCM(t *testing.T) *fakeFCM {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeFCM{key: key, messages: make(chan fcmMessage, 100), answers: map[string][2]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" || !f.validJWT(r.Form.Get("assertion")) {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.logins++
		f.mu.Unlock()
		fmt.Fprintf(w, `{"access_token":%q,"expires_in":3599,"token_type":"Bearer"}`, fakeAccessToken)
	})
	mux.HandleFunc("POST /v1/projects/talk-test/messages:send", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+fakeAccessToken {
			http.Error(w, `{"error":{"code":401,"status":"UNAUTHENTICATED"}}`, http.StatusUnauthorized)
			return
		}
		var body struct{ Message fcmMessage }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		answer, ok := f.answers[body.Message.Token]
		f.mu.Unlock()
		if ok {
			w.WriteHeader(map[string]int{"404": 404, "400": 400, "503": 503}[answer[0]])
			fmt.Fprintf(w, `{"error":{"code":%s,"status":"NOT_FOUND","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":%q}]}}`,
				answer[0], answer[1])
			return
		}
		f.messages <- body.Message
		fmt.Fprint(w, `{"name":"projects/talk-test/messages/1"}`)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// validJWT checks an RS256 JWT signed by the service account's key, for the FCM scope.
func (f *fakeFCM) validJWT(jwt string) bool {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false
	}
	enc := base64.RawURLEncoding
	signature, err := enc.DecodeString(parts[2])
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(&f.key.PublicKey, crypto.SHA256, digest[:], signature) != nil {
		return false
	}
	var header map[string]string
	var claims map[string]any
	h, _ := enc.DecodeString(parts[0])
	c, _ := enc.DecodeString(parts[1])
	if json.Unmarshal(h, &header) != nil || json.Unmarshal(c, &claims) != nil {
		return false
	}
	return header["alg"] == "RS256" && header["kid"] == "key-1" && claims["iss"] == "ptt@talk-test.iam.gserviceaccount.com" &&
		claims["scope"] == "https://www.googleapis.com/auth/firebase.messaging" && claims["aud"] == f.URL+"/token"
}

// serviceAccount writes a service-account key file for the fake, as Firebase's console downloads one.
func (f *fakeFCM) serviceAccount(t *testing.T) string {
	t.Helper()
	der, _ := x509.MarshalPKCS8PrivateKey(f.key)
	data, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "talk-test", "private_key_id": "key-1",
		"private_key":  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})),
		"client_email": "ptt@talk-test.iam.gserviceaccount.com", "token_uri": f.URL + "/token",
	})
	path := filepath.Join(t.TempDir(), "talk-test-firebase-adminsdk-test.json")
	os.WriteFile(path, data, 0o600)
	return path
}

func (f *fakeFCM) answer(token, status, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[token] = [2]string{status, code}
}

// next is the next message the fake got, waiting up to 5 seconds.
func (f *fakeFCM) next(t *testing.T) fcmMessage {
	t.Helper()
	select {
	case m := <-f.messages:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no push in 5 seconds")
		return fcmMessage{}
	}
}

// none checks that no message comes for a while.
func (f *fakeFCM) none(t *testing.T, wait time.Duration) {
	t.Helper()
	select {
	case m := <-f.messages:
		t.Fatalf("an unexpected push: %+v", m)
	case <-time.After(wait):
	}
}

// pushWindow is the debounce in the tests, short so they stay quick.
const pushWindow = 300 * time.Millisecond

// newPushEnv is a test server with FCM set up to reach the fake.
func newPushEnv(t *testing.T) (*testEnv, *fakeFCM) {
	t.Helper()
	fcm := newFakeFCM(t)
	account := fcm.serviceAccount(t)
	env := newTestEnv(t, func(c *auth.AppConfig) {
		c.FCM = &auth.FCMConfig{ServiceAccountFile: account, Endpoint: fcm.URL}
	})
	env.relay.Push.Window = pushWindow
	env.relay.Push.RetryAfter = 10 * time.Millisecond
	return env, fcm
}

func (e *testEnv) registerPush(t *testing.T, p *phone, token any, notifications bool) gqlResponse {
	t.Helper()
	return e.graphql(t, p.client, `mutation($t: String, $n: Boolean!) { registerPush(token: $t, notificationsEnabled: $n) }`,
		map[string]any{"t": token, "n": notifications})
}

// sendKind sends one envelope to each device of to, asking for the wake-up kind.
func (s *socket) sendKind(t *testing.T, kind pb.PushKind, to ...store.Device) *pb.SendResult {
	t.Helper()
	send := &pb.Send{ClientId: fmt.Sprint(time.Now().UnixNano()), PushKind: kind}
	for _, d := range to {
		send.Envelopes = append(send.Envelopes, &pb.Envelope{RecipientUser: d.User, RecipientDevice: uint32(d.Number),
			Type: pb.Envelope_MESSAGE, Ciphertext: []byte("ciphertext")})
	}
	s.write(t, &pb.Frame{Kind: &pb.Frame_Send{Send: send}})
	result := s.next(t, "send_result").GetSendResult()
	if result.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("send: %v", result)
	}
	return result
}

func (e *testEnv) closeSocket(t *testing.T, s *socket, p *phone) {
	t.Helper()
	s.ws.Close(websocket.StatusNormalClosure, "")
	waitFor(t, func() bool { return !e.relay.Connected(dev(p)) })
}

// hen (phone and tablet) and dana (phone), paired, with sockets open.
func pushedPair(t *testing.T, env *testEnv) (henPhone, henTablet, danaPhone *phone, henSocket, tabletSocket, danaSocket *socket) {
	t.Helper()
	env.addUsers(t, "hen", "dana")
	henPhone, henTablet, danaPhone = env.phone(t, "hen"), env.phone(t, "hen"), env.phone(t, "dana")
	identity := ecKey()
	env.uploadKeys(t, henPhone, identity)
	env.uploadKeys(t, henTablet, identity)
	env.uploadKeys(t, danaPhone, ecKey())
	henSocket, tabletSocket, danaSocket = env.socket(t, henPhone), env.socket(t, henTablet), env.socket(t, danaPhone)
	env.pair(t, henPhone, []store.Device{dev(henPhone), dev(henTablet)}, danaPhone, danaSocket)
	return
}

// A device without /ws gets a data-only push holding only the kind, at the priority its kind and its
// notifications call for; a connected one gets none, and the sender's own devices get sync at most.
func TestAnOfflineDeviceIsWokenByPush(t *testing.T) {
	env, fcm := newPushEnv(t)
	henPhone, henTablet, danaPhone, henSocket, tabletSocket, danaSocket := pushedPair(t, env)
	if r := env.registerPush(t, danaPhone, "dana-token", true); len(r.Errors) > 0 || string(r.Data["registerPush"]) != "true" {
		t.Fatalf("registerPush: %s %+v", r.Data["registerPush"], r.Errors)
	}
	env.registerPush(t, henTablet, "tablet-token", true)
	info := env.graphql(t, danaPhone.client, `{ serverInfo { push } me { pushRegistered notificationsEnabled } }`, nil)
	if string(info.Data["me"]) != `{"pushRegistered":true,"notificationsEnabled":true}` || string(info.Data["serverInfo"]) != `{"push":true}` {
		t.Fatalf("serverInfo and me: %s %+v", mustJSON(info.Data), info.Errors)
	}

	// Connected: the envelopes go over /ws and nothing is pushed.
	henSocket.sendKind(t, pb.PushKind_PUSH_MESSAGE, dev(danaPhone), dev(henTablet))
	danaSocket.envelope(t)
	tabletSocket.envelope(t)
	fcm.none(t, 200*time.Millisecond)

	// Offline: a message is high priority for dana, and only a sync for hen's own tablet.
	env.closeSocket(t, danaSocket, danaPhone)
	env.closeSocket(t, tabletSocket, henTablet)
	henSocket.sendKind(t, pb.PushKind_PUSH_MESSAGE, dev(danaPhone), dev(henTablet))
	got := map[string]fcmMessage{}
	for range 2 {
		m := fcm.next(t)
		got[m.Token] = m
	}
	if m := got["dana-token"]; len(m.Data) != 1 || m.Data["kind"] != "message" || m.Android.Priority != "HIGH" ||
		m.Android.TTL != "" || m.Android.CollapseKey != "message" {
		t.Fatalf("dana's push: %+v", m)
	}
	if m := got["tablet-token"]; len(m.Data) != 1 || m.Data["kind"] != "sync" || m.Android.Priority != "NORMAL" ||
		m.Android.TTL != "86400s" || m.Android.CollapseKey != "sync" {
		t.Fatalf("the tablet's push: %+v", m)
	}

	// After the window: a Send without a kind is a sync, typing (NONE) pushes nothing.
	time.Sleep(pushWindow + 50*time.Millisecond)
	henSocket.sendKind(t, pb.PushKind_PUSH_NONE, dev(danaPhone), dev(henTablet))
	fcm.none(t, pushWindow+100*time.Millisecond)
	henSocket.sendKind(t, pb.PushKind_PUSH_KIND_UNSPECIFIED, dev(danaPhone), dev(henTablet))
	for range 2 {
		if m := fcm.next(t); m.Data["kind"] != "sync" || m.Android.Priority != "NORMAL" {
			t.Fatalf("a push for a send without a kind: %+v", m)
		}
	}

	// Notifications off: a message is pushed at normal priority, so FCM doesn't lower the app's.
	time.Sleep(pushWindow + 50*time.Millisecond)
	env.registerPush(t, danaPhone, "dana-token", false)
	henSocket.sendKind(t, pb.PushKind_PUSH_MESSAGE, dev(danaPhone), dev(henTablet))
	for range 2 {
		if m := fcm.next(t); m.Token == "dana-token" && (m.Data["kind"] != "message" || m.Android.Priority != "NORMAL") {
			t.Fatalf("a message with notifications off: %+v", m)
		}
	}

	// A server-made envelope (PAIRED) pushes a sync.
	time.Sleep(pushWindow + 50*time.Millisecond)
	env.addUser(t, "eve")
	evePhone := env.phone(t, "eve")
	env.uploadKeys(t, evePhone, ecKey())
	eveSocket := env.socket(t, evePhone)
	token := env.pairingToken(t, danaPhone)
	env.bundles(t, evePhone, "dana", token)
	if r := eveSocket.send(t, pb.Envelope_PREKEY_MESSAGE, token, dev(danaPhone)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("eve's pair request: %v", r)
	}
	if m := fcm.next(t); m.Token != "dana-token" || m.Data["kind"] != "sync" {
		t.Fatalf("the pair request's push: %+v", m)
	}
	_ = henPhone
}

// A burst of envelopes gives one push at once and one more, of the most urgent kind, at the end of the window; and
// none when the device connected meanwhile.
func TestPushesAreDebounced(t *testing.T) {
	env, fcm := newPushEnv(t)
	_, _, danaPhone, henSocket, tabletSocket, danaSocket := pushedPair(t, env)
	tabletSocket.ws.Close(websocket.StatusNormalClosure, "") // so hen's Sends only need dana's device and the tablet's
	env.registerPush(t, danaPhone, "dana-token", true)
	env.closeSocket(t, danaSocket, danaPhone)
	henTablet := store.Device{User: "hen", Number: 2}

	henSocket.sendKind(t, pb.PushKind_PUSH_SYNC, dev(danaPhone), henTablet)
	for range 4 {
		henSocket.sendKind(t, pb.PushKind_PUSH_SYNC, dev(danaPhone), henTablet)
	}
	henSocket.sendKind(t, pb.PushKind_PUSH_MESSAGE, dev(danaPhone), henTablet)
	henSocket.sendKind(t, pb.PushKind_PUSH_SYNC, dev(danaPhone), henTablet)
	if m := fcm.next(t); m.Data["kind"] != "sync" {
		t.Fatalf("the first push: %+v", m)
	}
	if m := fcm.next(t); m.Data["kind"] != "message" || m.Android.Priority != "HIGH" {
		t.Fatalf("the push at the window's end: %+v", m)
	}
	fcm.none(t, 2*pushWindow)

	// Within the next window the device connects: the push waiting is dropped.
	henSocket.sendKind(t, pb.PushKind_PUSH_MESSAGE, dev(danaPhone), henTablet)
	fcm.next(t)
	henSocket.sendKind(t, pb.PushKind_PUSH_MESSAGE, dev(danaPhone), henTablet)
	env.socket(t, danaPhone)
	fcm.none(t, 2*pushWindow)
}

// A token FCM answers as gone is dropped from the registry; revoking a device clears its token; a token moves to
// the device that registers it last; a malformed token is refused.
func TestPushTokensAreKeptAndDropped(t *testing.T) {
	env, fcm := newPushEnv(t)
	henPhone, henTablet, danaPhone, henSocket, tabletSocket, danaSocket := pushedPair(t, env)
	env.registerPush(t, danaPhone, "dana-token", true)
	env.closeSocket(t, danaSocket, danaPhone)
	env.closeSocket(t, tabletSocket, henTablet)

	fcm.answer("dana-token", "404", "UNREGISTERED")
	henSocket.sendKind(t, pb.PushKind_PUSH_MESSAGE, dev(danaPhone), dev(henTablet))
	waitFor(t, func() bool {
		d, _ := env.enrollment.Registry.Find(danaPhone.serial)
		return d.FCMToken == "" && !d.NotificationsEnabled
	})
	if r := env.graphql(t, danaPhone.client, `{ me { pushRegistered } }`, nil); string(r.Data["me"]) != `{"pushRegistered":false}` {
		t.Fatalf("me after the token was dropped: %s", r.Data["me"])
	}

	// A failure that passes (503) is tried again.
	env.registerPush(t, danaPhone, "dana-token-2", true)
	fcm.answer("dana-token-2", "503", "UNAVAILABLE")
	time.Sleep(pushWindow + 50*time.Millisecond)
	henSocket.sendKind(t, pb.PushKind_PUSH_MESSAGE, dev(danaPhone), dev(henTablet))
	time.Sleep(100 * time.Millisecond)
	if d, _ := env.enrollment.Registry.Find(danaPhone.serial); d.FCMToken != "dana-token-2" {
		t.Fatalf("a 503 dropped the token: %+v", d)
	}

	// The same token registered by another device moves there; null clears it.
	env.registerPush(t, henTablet, "shared-token", true)
	env.registerPush(t, henPhone, "shared-token", false)
	if d, _ := env.enrollment.Registry.Find(henTablet.serial); d.FCMToken != "" {
		t.Fatalf("the tablet kept a token the phone took: %+v", d)
	}
	env.registerPush(t, henPhone, nil, true)
	if d, _ := env.enrollment.Registry.Find(henPhone.serial); d.FCMToken != "" || d.NotificationsEnabled {
		t.Fatalf("a null token: %+v", d)
	}
	for _, bad := range []string{"with space", strings.Repeat("x", 4097), "tab\there"} {
		if code := errorCode(env.registerPush(t, henPhone, bad, true)); code != "INVALID_TOKEN" {
			t.Fatalf("registerPush(%.20q): %s", bad, code)
		}
	}

	// Revoking clears the token at once.
	env.registerPush(t, henTablet, "tablet-token", true)
	var data struct{ RevokeDevice adminDevice }
	if err := adminQuery(env.adminConfig, `mutation($s: String!) { revokeDevice(serial: $s) { serial } }`,
		map[string]any{"s": henTablet.serial}, &data); err != nil {
		t.Fatal(err)
	}
	if d, _ := env.enrollment.Registry.Find(henTablet.serial); d.FCMToken != "" || d.NotificationsEnabled {
		t.Fatalf("the revoked tablet kept its token: %+v", d)
	}
	saved, _ := os.ReadFile(env.config.DevicesFile)
	if strings.Contains(string(saved), "tablet-token") {
		t.Fatal("devices.json still holds the revoked tablet's token")
	}
}

// Without fcm in config.json the server runs with no push: registerPush still stores the token, Sends work, and
// serverInfo.push says so.
func TestNoFCMNoPush(t *testing.T) {
	env := newTestEnv(t)
	_, _, danaPhone, henSocket, tabletSocket, danaSocket := pushedPair(t, env)
	if r := env.registerPush(t, danaPhone, "dana-token", true); string(r.Data["registerPush"]) != "true" {
		t.Fatalf("registerPush: %+v", r)
	}
	if r := env.graphql(t, danaPhone.client, `{ serverInfo { push } }`, nil); string(r.Data["serverInfo"]) != `{"push":false}` {
		t.Fatalf("serverInfo: %s", r.Data["serverInfo"])
	}
	env.closeSocket(t, danaSocket, danaPhone)
	tabletSocket.ws.Close(websocket.StatusNormalClosure, "")
	henSocket.sendKind(t, pb.PushKind_PUSH_MESSAGE, dev(danaPhone), store.Device{User: "hen", Number: 2})
	if n, _ := env.store.QueueLength(dev(danaPhone)); n == 0 {
		t.Fatal("nothing queued")
	}
}

// Contacts see each other's presence, by the query and live frames; others don't, and hiding works both ways.
func TestPresence(t *testing.T) {
	env := newTestEnv(t)
	henPhone, henTablet, danaPhone, henSocket, tabletSocket, danaSocket := pushedPair(t, env)
	env.addUser(t, "eve")
	evePhone := env.phone(t, "eve")
	env.socket(t, evePhone)

	type presence struct {
		User     string
		Online   bool
		LastSeen *time.Time
	}
	query := func(p *phone, users ...string) []presence {
		t.Helper()
		r := env.graphql(t, p.client, `query($u: [String!]!) { presence(users: $u) { user online lastSeen } }`, map[string]any{"u": users})
		var out []presence
		if err := json.Unmarshal(r.Data["presence"], &out); err != nil || len(r.Errors) > 0 {
			t.Fatalf("presence: %s %+v", r.Data["presence"], r.Errors)
		}
		return out
	}
	if got := query(danaPhone, "hen", "eve", "nobody"); len(got) != 1 || got[0].User != "hen" || !got[0].Online || got[0].LastSeen != nil {
		t.Fatalf("presence of hen, eve and nobody: %+v", got)
	}
	if got := query(evePhone, "hen", "dana"); len(got) != 0 {
		t.Fatalf("presence for someone who isn't a contact: %+v", got)
	}

	// One device going leaves hen online; the last one going sends dana a Presence frame.
	env.closeSocket(t, tabletSocket, henTablet)
	if got := query(danaPhone, "hen"); !got[0].Online {
		t.Fatalf("hen with one device still connected: %+v", got)
	}
	env.closeSocket(t, henSocket, henPhone)
	f := danaSocket.next(t, "presence").GetPresence()
	if f.User != "hen" || f.Online || f.LastSeen == 0 || f.LastSeen%(5*60*1000) != 0 {
		t.Fatalf("the offline frame: %v", f)
	}
	if got := query(danaPhone, "hen"); got[0].Online || got[0].LastSeen == nil || got[0].LastSeen.UnixMilli() != f.LastSeen {
		t.Fatalf("hen offline: %+v", got)
	}
	henSocket = env.socket(t, henPhone)
	if f := danaSocket.next(t, "presence").GetPresence(); f.User != "hen" || !f.Online {
		t.Fatalf("the online frame: %v", f)
	}
	// hen hears of dana too.
	env.closeSocket(t, danaSocket, danaPhone)
	if f := henSocket.next(t, "presence").GetPresence(); f.User != "dana" || f.Online {
		t.Fatalf("hen's frame about dana: %v", f)
	}
	danaSocket = env.socket(t, danaPhone)
	henSocket.next(t, "presence")

	// dana hides: dana sees hen as offline with no last seen, hen sees the same of dana, and no frames go.
	r := env.graphql(t, danaPhone.client, `mutation { setPresenceVisible(visible: false) }`, nil)
	if string(r.Data["setPresenceVisible"]) != "false" {
		t.Fatalf("setPresenceVisible: %+v", r)
	}
	if r := env.graphql(t, danaPhone.client, `{ me { presenceVisible } }`, nil); string(r.Data["me"]) != `{"presenceVisible":false}` {
		t.Fatalf("me: %s", r.Data["me"])
	}
	if got := query(danaPhone, "hen"); got[0].Online || got[0].LastSeen != nil {
		t.Fatalf("hen seen by dana, who hides: %+v", got)
	}
	if got := query(henPhone, "dana"); got[0].Online || got[0].LastSeen != nil {
		t.Fatalf("dana, who hides, seen by hen: %+v", got)
	}
	// hen's devices come and go: dana, connected, hears nothing of it.
	env.closeSocket(t, henSocket, henPhone)
	env.socket(t, henPhone)
	time.Sleep(200 * time.Millisecond)
	for len(danaSocket.frames) > 0 {
		danaSocket.backlog = append(danaSocket.backlog, <-danaSocket.frames)
	}
	for _, f := range danaSocket.backlog {
		if kindOf(f) == "presence" {
			t.Fatalf("a presence frame while dana hides: %v", f)
		}
	}
}

// Opening a chat warms the other phone (2026-11-24, hen): a "warm" push at high priority where notifications are on,
// kept 60 seconds, for the other user only (the sender's own devices get a sync at most); normal priority with
// notifications off.
func TestAWarmPushIsHighPriorityAndShort(t *testing.T) {
	env, fcm := newPushEnv(t)
	_, henTablet, danaPhone, henSocket, tabletSocket, danaSocket := pushedPair(t, env)
	env.registerPush(t, danaPhone, "dana-token", true)
	env.registerPush(t, henTablet, "tablet-token", true)
	env.closeSocket(t, danaSocket, danaPhone)
	env.closeSocket(t, tabletSocket, henTablet)
	henSocket.sendKind(t, pb.PushKind_PUSH_WARM, dev(danaPhone), dev(henTablet))
	got := map[string]fcmMessage{}
	for range 2 {
		m := fcm.next(t)
		got[m.Token] = m
	}
	if m := got["dana-token"]; len(m.Data) != 1 || m.Data["kind"] != "warm" || m.Android.Priority != "HIGH" ||
		m.Android.TTL != "60s" || m.Android.CollapseKey != "warm" {
		t.Fatalf("dana's warm push: %+v", m)
	}
	if m := got["tablet-token"]; m.Data["kind"] != "sync" || m.Android.Priority != "NORMAL" {
		t.Fatalf("hen's own tablet: %+v", m)
	}

	// Notifications off: normal priority.
	time.Sleep(pushWindow + 50*time.Millisecond)
	env.registerPush(t, danaPhone, "dana-token", false)
	henSocket.sendKind(t, pb.PushKind_PUSH_WARM, dev(danaPhone), dev(henTablet))
	for range 2 {
		if m := fcm.next(t); m.Token == "dana-token" && (m.Data["kind"] != "warm" || m.Android.Priority != "NORMAL") {
			t.Fatalf("a warm push with notifications off: %+v", m)
		}
	}
}
