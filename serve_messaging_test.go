package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"
)

// phone is an enrolled device in a test, with the client and certificate it reaches the server with.
type phone struct {
	user     string
	number   int
	serial   string
	client   *http.Client
	cert     tls.Certificate
	identity []byte
}

func (e *testEnv) phone(t *testing.T, user string) *phone {
	t.Helper()
	client, enrolled, cert := e.device(t, user)
	return &phone{user: user, number: enrolled.DeviceNumber, serial: enrolled.Serial, client: client, cert: cert}
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// ecKey and kyberKey are public keys of libsignal's serialized sizes; the server checks no more than that.
func ecKey() []byte       { return append([]byte{0x05}, randomBytes(32)...) }
func kyberKey() []byte    { return append([]byte{0x08}, randomBytes(1568)...) }
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func signed(id int, public []byte) map[string]any {
	return map[string]any{"keyId": id, "publicKey": b64(public), "signature": b64(randomBytes(64))}
}

const uploadMutation = `mutation($input: UploadPrekeysInput!) {
	uploadPrekeys(input: $input) { oneTimePrekeys oneTimeKyberPrekeys refillBelow }
}`

// keysInput is a first upload: identity, signed and last-resort prekeys, and n one-time prekeys of each kind with
// ids from first.
func keysInput(identity []byte, registration, first, n int) map[string]any {
	var ec, kyber []map[string]any
	for i := range n {
		ec = append(ec, map[string]any{"keyId": first + i, "publicKey": b64(ecKey())})
		kyber = append(kyber, signed(first+i, kyberKey()))
	}
	return map[string]any{
		"identityKey":           b64(identity),
		"registrationId":        registration,
		"signedPrekey":          signed(1, ecKey()),
		"kyberLastResortPrekey": signed(9999, kyberKey()),
		"oneTimePrekeys":        ec,
		"oneTimeKyberPrekeys":   kyber,
	}
}

// uploadKeys uploads p's first keys under identity (the user's), with 3 one-time prekeys of each kind.
func (e *testEnv) uploadKeys(t *testing.T, p *phone, identity []byte) {
	t.Helper()
	p.identity = identity
	r := e.graphql(t, p.client, uploadMutation, map[string]any{"input": keysInput(identity, 1000+p.number, 100, 3)})
	if len(r.Errors) > 0 || string(r.Data["uploadPrekeys"]) != `{"oneTimePrekeys":3,"oneTimeKyberPrekeys":3,"refillBelow":20}` {
		t.Fatalf("uploadPrekeys of %s.%d: %s %+v", p.user, p.number, r.Data["uploadPrekeys"], r.Errors)
	}
}

// errorCode is the code of the first error of r, or "".
func errorCode(r gqlResponse) string {
	if len(r.Errors) == 0 {
		return ""
	}
	code, _ := r.Errors[0].Extensions["code"].(string)
	return code
}

type bundles struct {
	User        string
	IdentityKey string
	Devices     []struct {
		DeviceNumber   int
		RegistrationID int
		SignedPrekey   struct{ KeyID int }
		Prekey         *struct{ KeyID int }
		KyberPrekey    struct {
			KeyID      int
			LastResort bool
		}
	}
}

const bundlesQuery = `query($user: String!, $token: String) {
	prekeyBundles(user: $user, routingToken: $token) {
		user identityKey
		devices { deviceNumber registrationId signedPrekey { keyId publicKey signature } prekey { keyId publicKey }
			kyberPrekey { keyId publicKey signature lastResort } }
	}
}`

func (e *testEnv) bundles(t *testing.T, p *phone, user, token string) (bundles, string) {
	t.Helper()
	vars := map[string]any{"user": user}
	if token != "" {
		vars["token"] = token
	}
	r := e.graphql(t, p.client, bundlesQuery, vars)
	var b bundles
	if code := errorCode(r); code != "" || len(r.Errors) > 0 {
		return b, fmt.Sprint(code, r.Errors)
	}
	json.Unmarshal(r.Data["prekeyBundles"], &b)
	return b, ""
}

func (e *testEnv) pairingToken(t *testing.T, p *phone) string {
	t.Helper()
	r := e.graphql(t, p.client, `mutation { pairingToken { token expiresAt } }`, nil)
	var got struct{ Token string }
	json.Unmarshal(r.Data["pairingToken"], &got)
	if len(r.Errors) > 0 || len(got.Token) != 22 {
		t.Fatalf("pairingToken: %s %+v", r.Data["pairingToken"], r.Errors)
	}
	return got.Token
}

func (e *testEnv) mutate(t *testing.T, p *phone, field, user string) (string, string) {
	t.Helper()
	r := e.graphql(t, p.client, `mutation($u: String!) { `+field+`(user: $u) }`, map[string]any{"u": user})
	return strings.Trim(string(r.Data[field]), `"`), errorCode(r)
}

// socket is a device's /ws connection in a test. Frames that arrive are kept until a test asks for their kind.
type socket struct {
	ws      *websocket.Conn
	frames  chan *pb.Frame
	closed  chan error
	backlog []*pb.Frame
}

// socket connects p to /ws over HTTP/1.1, as OkHttp's WebSocket does.
func (e *testEnv) socket(t *testing.T, p *phone) *socket {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.roots,
		Certificates: []tls.Certificate{p.cert}, NextProtos: []string{"http/1.1"}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, resp, err := websocket.Dial(ctx, "wss"+strings.TrimPrefix(e.public.URL, "https")+"/ws",
		&websocket.DialOptions{HTTPClient: client})
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("/ws for %s.%d: %v (%d)", p.user, p.number, err, status)
	}
	ws.SetReadLimit(8 << 20)
	s := &socket{ws: ws, frames: make(chan *pb.Frame, 100), closed: make(chan error, 1)}
	go func() {
		for {
			_, data, err := ws.Read(context.Background())
			if err != nil {
				s.closed <- err
				close(s.frames)
				return
			}
			var f pb.Frame
			if err := proto.Unmarshal(data, &f); err != nil {
				s.closed <- err
				close(s.frames)
				return
			}
			s.frames <- &f
		}
	}()
	t.Cleanup(func() { ws.CloseNow() })
	s.next(t, "queue_empty")
	return s
}

func kindOf(f *pb.Frame) string {
	switch f.Kind.(type) {
	case *pb.Frame_Envelope:
		return "envelope"
	case *pb.Frame_SendResult:
		return "send_result"
	case *pb.Frame_QueueEmpty:
		return "queue_empty"
	case *pb.Frame_Pong:
		return "pong"
	case *pb.Frame_Presence:
		return "presence"
	case *pb.Frame_TalkState:
		return "talk_state"
	case *pb.Frame_ClipSegment:
		return "clip_segment"
	}
	return "other"
}

// next is the next frame of kind, waiting up to 5 seconds.
func (s *socket) next(t *testing.T, kind string) *pb.Frame {
	t.Helper()
	for i, f := range s.backlog {
		if kindOf(f) == kind {
			s.backlog = append(s.backlog[:i], s.backlog[i+1:]...)
			return f
		}
	}
	timeout := time.After(5 * time.Second)
	for {
		select {
		case f, ok := <-s.frames:
			if !ok {
				t.Fatalf("the socket closed waiting for %s", kind)
			}
			if kindOf(f) == kind {
				return f
			}
			s.backlog = append(s.backlog, f)
		case <-timeout:
			t.Fatalf("no %s in 5 seconds", kind)
		}
	}
}

func (s *socket) envelope(t *testing.T) *pb.Envelope {
	t.Helper()
	return s.next(t, "envelope").GetEnvelope()
}

// quiet checks that no envelope arrives for a moment.
func (s *socket) quiet(t *testing.T) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	for {
		select {
		case f, ok := <-s.frames:
			if !ok {
				return
			}
			s.backlog = append(s.backlog, f)
			continue
		default:
		}
		break
	}
	for _, f := range s.backlog {
		if kindOf(f) == "envelope" {
			t.Fatalf("an envelope arrived: %v", f.GetEnvelope())
		}
	}
}

func (s *socket) write(t *testing.T, f *pb.Frame) {
	t.Helper()
	data, _ := proto.Marshal(f)
	if err := s.ws.Write(context.Background(), websocket.MessageBinary, data); err != nil {
		t.Fatal(err)
	}
}

// send sends an envelope of kind to each device of to, with token when it isn't "" and returns the result.
func (s *socket) send(t *testing.T, kind pb.Envelope_Type, token string, to ...store.Device) *pb.SendResult {
	t.Helper()
	send := &pb.Send{ClientId: fmt.Sprint(time.Now().UnixNano())}
	for _, d := range to {
		send.Envelopes = append(send.Envelopes, &pb.Envelope{RecipientUser: d.User, RecipientDevice: uint32(d.Number),
			Type: kind, Ciphertext: []byte("ciphertext for " + d.User), RoutingToken: token})
	}
	s.write(t, &pb.Frame{Kind: &pb.Frame_Send{Send: send}})
	result := s.next(t, "send_result").GetSendResult()
	if result.ClientId != send.ClientId {
		t.Fatalf("result for %s, sent %s", result.ClientId, send.ClientId)
	}
	return result
}

func (s *socket) ack(t *testing.T, ids ...string) {
	t.Helper()
	s.write(t, &pb.Frame{Kind: &pb.Frame_Ack{Ack: &pb.Ack{Ids: ids}}})
}

// closedWith waits for the server to close the socket, and is the close code.
func (s *socket) closedWith(t *testing.T) websocket.StatusCode {
	t.Helper()
	for {
		select {
		case _, ok := <-s.frames:
			if ok {
				continue
			}
			return websocket.CloseStatus(<-s.closed)
		case <-time.After(5 * time.Second):
			t.Fatal("the socket is still open")
		}
	}
}

func dev(p *phone) store.Device { return store.Device{User: p.user, Number: p.number} }

func (e *testEnv) addUsers(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		e.addUser(t, n)
	}
}

// pair makes a and b contacts the way two phones do: a shows a pairing token, b sends a pair request with it to
// every device of a, and both confirm.
func (e *testEnv) pair(t *testing.T, a *phone, aDevices []store.Device, b *phone, bSocket *socket) {
	t.Helper()
	token := e.pairingToken(t, a)
	if _, problem := e.bundles(t, b, a.user, token); problem != "" {
		t.Fatalf("bundles with a token: %s", problem)
	}
	if r := bSocket.send(t, pb.Envelope_PREKEY_MESSAGE, token, aDevices...); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("pair request: %v", r)
	}
	if state, code := e.mutate(t, b, "confirmPair", a.user); state != "WAITING" {
		t.Fatalf("confirmPair by %s: %s %s", b.user, state, code)
	}
	if state, code := e.mutate(t, a, "confirmPair", b.user); state != "PAIRED" {
		t.Fatalf("confirmPair by %s: %s %s", a.user, state, code)
	}
}

// Phase 2 from the server's side: two users enroll and upload keys, one pairs with the other's QR code (a pairing
// token), both confirm, and envelopes then go both ways over /ws, queued for a device that is away and sent again
// after a reconnect until it acknowledges them.
func TestTwoUsersPairAndExchangeEnvelopes(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana")
	henPhone, henTablet, danaPhone := env.phone(t, "hen"), env.phone(t, "hen"), env.phone(t, "dana")
	henIdentity := ecKey()
	env.uploadKeys(t, henPhone, henIdentity)
	env.uploadKeys(t, henTablet, henIdentity)
	env.uploadKeys(t, danaPhone, ecKey())
	hen := []store.Device{dev(henPhone), dev(henTablet)}

	// Before pairing, dana can't reach hen.
	if _, problem := env.bundles(t, danaPhone, "hen", ""); !strings.HasPrefix(problem, "NOT_PAIRED") {
		t.Fatalf("bundles without pairing: %s", problem)
	}
	if _, problem := env.bundles(t, danaPhone, "hen", "not-a-token"); !strings.HasPrefix(problem, "NOT_PAIRED") {
		t.Fatalf("bundles with a wrong token: %s", problem)
	}
	danaSocket := env.socket(t, danaPhone)
	henSocket, tabletSocket := env.socket(t, henPhone), env.socket(t, henTablet)
	if r := danaSocket.send(t, pb.Envelope_PREKEY_MESSAGE, "", hen...); r.Status != pb.SendResult_NOT_PAIRED {
		t.Fatalf("an unpaired send: %v", r)
	}

	// hen shows a QR code with a pairing token; dana fetches hen's bundles with it.
	token := env.pairingToken(t, henPhone)
	got, problem := env.bundles(t, danaPhone, "hen", token)
	if problem != "" || got.IdentityKey != b64(henIdentity) || len(got.Devices) != 2 ||
		got.Devices[0].DeviceNumber != 1 || got.Devices[1].DeviceNumber != 2 || got.Devices[0].RegistrationID != 1001 ||
		got.Devices[0].Prekey == nil || got.Devices[0].Prekey.KeyID != 100 || got.Devices[0].KyberPrekey.LastResort {
		t.Fatalf("bundles with a token: %+v %s", got, problem)
	}
	// The token isn't hen's for anyone else.
	if _, problem := env.bundles(t, danaPhone, "dana", token); problem != "" {
		t.Fatalf("own bundles: %s", problem)
	}

	// A pair request must reach every device of hen.
	r := danaSocket.send(t, pb.Envelope_PREKEY_MESSAGE, token, dev(henPhone))
	if r.Status != pb.SendResult_STALE_DEVICES || len(r.Devices) != 2 || r.Devices[1].User != "hen" ||
		len(r.Devices[1].Devices) != 2 || r.Devices[1].Devices[1].RegistrationId != 1002 {
		t.Fatalf("a pair request to one of two devices: %v", r)
	}
	r = danaSocket.send(t, pb.Envelope_PREKEY_MESSAGE, token, hen...)
	if r.Status != pb.SendResult_ACCEPTED || len(r.EnvelopeIds) != 2 {
		t.Fatalf("the pair request: %v", r)
	}
	for _, s := range []*socket{henSocket, tabletSocket} {
		e := s.envelope(t)
		if e.SenderUser != "dana" || e.SenderDevice != 1 || e.RecipientUser != "hen" || e.Type != pb.Envelope_PREKEY_MESSAGE ||
			e.RoutingToken != "" || string(e.Ciphertext) != "ciphertext for hen" || e.ServerTimestamp == 0 {
			t.Fatalf("hen got %v", e)
		}
		s.ack(t, e.Id)
	}
	// The token was for one message, and hen still can't answer before both confirm.
	if r := danaSocket.send(t, pb.Envelope_MESSAGE, token, hen...); r.Status != pb.SendResult_NOT_PAIRED {
		t.Fatalf("a second send with the token: %v", r)
	}
	if r := henSocket.send(t, pb.Envelope_MESSAGE, "", dev(danaPhone), dev(henTablet)); r.Status != pb.SendResult_NOT_PAIRED {
		t.Fatalf("hen before confirming: %v", r)
	}
	if state, code := env.mutate(t, danaPhone, "confirmPair", "hen"); state != "WAITING" {
		t.Fatalf("dana confirms: %s %s", state, code)
	}
	if r := henSocket.send(t, pb.Envelope_MESSAGE, "", dev(danaPhone), dev(henTablet)); r.Status != pb.SendResult_NOT_PAIRED {
		t.Fatalf("hen before hen confirmed: %v", r)
	}
	if state, code := env.mutate(t, henPhone, "confirmPair", "dana"); state != "PAIRED" {
		t.Fatalf("hen confirms: %s %s", state, code)
	}
	for _, s := range []*socket{henSocket, tabletSocket, danaSocket} {
		e := s.envelope(t)
		if e.Type != pb.Envelope_PAIRED || e.SenderUser == e.RecipientUser {
			t.Fatalf("PAIRED: %v", e)
		}
		s.ack(t, e.Id)
	}
	var list struct {
		Contacts []struct {
			User, IdentityKey string
			Blocked           bool
			Devices           []struct{ DeviceNumber, RegistrationID int }
		}
	}
	c := env.graphql(t, danaPhone.client, `{ contacts { user identityKey since blocked devices { deviceNumber registrationId } } }`, nil)
	json.Unmarshal(mustJSON(c.Data), &list)
	if len(list.Contacts) != 1 || list.Contacts[0].User != "hen" || list.Contacts[0].IdentityKey != b64(henIdentity) ||
		len(list.Contacts[0].Devices) != 2 || list.Contacts[0].Devices[1].RegistrationID != 1002 {
		t.Fatalf("contacts: %s %+v", mustJSON(c.Data), c.Errors)
	}

	// Paired: hen's phone writes to dana, with a copy for hen's tablet.
	if r := henSocket.send(t, pb.Envelope_PREKEY_MESSAGE, "", dev(danaPhone)); r.Status != pb.SendResult_STALE_DEVICES {
		t.Fatalf("a send without the copy for hen's tablet: %v", r)
	}
	if r := henSocket.send(t, pb.Envelope_PREKEY_MESSAGE, "", dev(danaPhone), dev(henTablet)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("hen to dana: %v", r)
	}
	first := danaSocket.envelope(t)
	if first.SenderUser != "hen" || first.SenderDevice != 1 || first.RecipientDevice != 1 {
		t.Fatalf("dana got %v", first)
	}
	if e := tabletSocket.envelope(t); e.SenderUser != "hen" || e.RecipientUser != "hen" || string(e.Ciphertext) != "ciphertext for hen" {
		t.Fatalf("hen's tablet got %v", e)
	} else {
		tabletSocket.ack(t, e.Id)
	}
	danaSocket.ack(t, first.Id)

	// A second message dana doesn't acknowledge comes again on the next connection, and only it.
	if r := henSocket.send(t, pb.Envelope_MESSAGE, "", dev(danaPhone), dev(henTablet)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("hen to dana again: %v", r)
	}
	second := danaSocket.envelope(t)
	danaSocket.ws.Close(websocket.StatusNormalClosure, "")
	again := env.socket(t, danaPhone) // waits for QueueEmpty, which comes after the queue
	if len(again.backlog) != 1 || again.backlog[0].GetEnvelope().GetId() != second.Id {
		t.Fatalf("after reconnecting dana got %v", again.backlog)
	}
	again.backlog = nil
	again.ack(t, second.Id)

	// dana answers while hen's tablet is away: it is queued and delivered when the tablet connects.
	tabletSocket.ws.Close(websocket.StatusNormalClosure, "")
	waitFor(t, func() bool { return !env.relay.Connected(dev(henTablet)) })
	if r := again.send(t, pb.Envelope_MESSAGE, "", hen...); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("dana to hen: %v", r)
	}
	if e := henSocket.envelope(t); e.SenderUser != "dana" {
		t.Fatalf("hen's phone got %v", e)
	}
	tablet := env.socket(t, henTablet)
	if len(tablet.backlog) != 2 || tablet.backlog[1].GetEnvelope().GetSenderUser() != "dana" {
		t.Fatalf("hen's tablet found %v", tablet.backlog) // hen's own second message (not acknowledged), and dana's
	}
}

func mustJSON(data map[string]json.RawMessage) []byte {
	b, _ := json.Marshal(data)
	return b
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for range 100 {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("timed out")
}

// A Send is refused unless it is to a contact, covers exactly the active devices, and is well formed.
func TestSendsAreChecked(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana", "eve")
	henPhone, danaPhone, evePhone := env.phone(t, "hen"), env.phone(t, "dana"), env.phone(t, "eve")
	for _, p := range []*phone{henPhone, danaPhone, evePhone} {
		env.uploadKeys(t, p, ecKey())
	}
	henSocket, danaSocket := env.socket(t, henPhone), env.socket(t, danaPhone)
	env.pair(t, danaPhone, []store.Device{dev(danaPhone)}, henPhone, henSocket)
	danaSocket.envelope(t) // the pair request
	danaSocket.envelope(t) // PAIRED
	henSocket.envelope(t)  // PAIRED

	for name, c := range map[string]struct {
		to   []store.Device
		kind pb.Envelope_Type
		want pb.SendResult_Status
	}{
		"to nobody":              {nil, pb.Envelope_MESSAGE, pb.SendResult_INVALID},
		"to an unknown user":     {[]store.Device{{User: "zed", Number: 1}}, pb.Envelope_MESSAGE, pb.SendResult_UNKNOWN_USER},
		"to someone not paired":  {[]store.Device{dev(evePhone)}, pb.Envelope_MESSAGE, pb.SendResult_NOT_PAIRED},
		"to two users":           {[]store.Device{dev(danaPhone), dev(evePhone)}, pb.Envelope_MESSAGE, pb.SendResult_INVALID},
		"to a device not there":  {[]store.Device{dev(danaPhone), {User: "dana", Number: 2}}, pb.Envelope_MESSAGE, pb.SendResult_STALE_DEVICES},
		"to itself":              {[]store.Device{dev(henPhone)}, pb.Envelope_MESSAGE, pb.SendResult_INVALID},
		"twice to one device":    {[]store.Device{dev(danaPhone), dev(danaPhone)}, pb.Envelope_MESSAGE, pb.SendResult_INVALID},
		"a type only the server": {[]store.Device{dev(danaPhone)}, pb.Envelope_PAIRED, pb.SendResult_INVALID},
		"provisioning to dana":   {[]store.Device{dev(danaPhone)}, pb.Envelope_PROVISIONING, pb.SendResult_INVALID},
		"the contact":            {[]store.Device{dev(danaPhone)}, pb.Envelope_MESSAGE, pb.SendResult_ACCEPTED},
	} {
		if r := henSocket.send(t, c.kind, "", c.to...); r.Status != c.want {
			t.Errorf("%s: %v, want %s", name, r, c.want)
		}
	}
	danaSocket.envelope(t)

	// A registration id that changed is stale too.
	send := &pb.Send{ClientId: "x", Envelopes: []*pb.Envelope{{RecipientUser: "dana", RecipientDevice: 1,
		Type: pb.Envelope_MESSAGE, Ciphertext: []byte("x"), RecipientRegistrationId: 4242}}}
	henSocket.write(t, &pb.Frame{Kind: &pb.Frame_Send{Send: send}})
	if r := henSocket.next(t, "send_result").GetSendResult(); r.Status != pb.SendResult_STALE_DEVICES {
		t.Errorf("an old registration id: %v", r)
	}
	// Too large.
	send.Envelopes[0].RecipientRegistrationId = 0
	send.Envelopes[0].Ciphertext = bytes.Repeat([]byte("x"), 256<<10+1)
	henSocket.write(t, &pb.Frame{Kind: &pb.Frame_Send{Send: send}})
	if r := henSocket.next(t, "send_result").GetSendResult(); r.Status != pb.SendResult_TOO_LARGE {
		t.Errorf("a 256 KB + 1 envelope: %v", r)
	}
	// A ping is answered.
	henSocket.write(t, &pb.Frame{Kind: &pb.Frame_Ping{Ping: &pb.Ping{Id: 7}}})
	if p := henSocket.next(t, "pong").GetPong(); p.Id != 7 {
		t.Errorf("pong %v", p)
	}
	danaSocket.quiet(t)
}

// A block stops everything both ways at once, and unblocking brings the pair back; unpairing ends it.
func TestBlockAndUnpair(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana")
	henPhone, danaPhone := env.phone(t, "hen"), env.phone(t, "dana")
	env.uploadKeys(t, henPhone, ecKey())
	env.uploadKeys(t, danaPhone, ecKey())
	henSocket, danaSocket := env.socket(t, henPhone), env.socket(t, danaPhone)
	env.pair(t, danaPhone, []store.Device{dev(danaPhone)}, henPhone, henSocket)

	if ok, code := env.mutate(t, danaPhone, "block", "hen"); ok != "true" {
		t.Fatalf("block: %s %s", ok, code)
	}
	if r := henSocket.send(t, pb.Envelope_MESSAGE, "", dev(danaPhone)); r.Status != pb.SendResult_BLOCKED {
		t.Fatalf("to the user who blocked: %v", r)
	}
	if r := danaSocket.send(t, pb.Envelope_MESSAGE, "", dev(henPhone)); r.Status != pb.SendResult_BLOCKED {
		t.Fatalf("to the user blocked: %v", r)
	}
	if _, problem := env.bundles(t, henPhone, "dana", ""); !strings.HasPrefix(problem, "BLOCKED") {
		t.Fatalf("bundles of the user who blocked: %s", problem)
	}
	// A new pairing token of dana doesn't help hen either.
	token := env.pairingToken(t, danaPhone)
	if _, problem := env.bundles(t, henPhone, "dana", token); !strings.HasPrefix(problem, "BLOCKED") {
		t.Fatalf("bundles with a token, blocked: %s", problem)
	}
	if r := henSocket.send(t, pb.Envelope_PREKEY_MESSAGE, token, dev(danaPhone)); r.Status != pb.SendResult_BLOCKED {
		t.Fatalf("a pair request, blocked: %v", r)
	}
	b := env.graphql(t, danaPhone.client, `{ blocked contacts { user blocked } }`, nil)
	if string(b.Data["blocked"]) != `["hen"]` || string(b.Data["contacts"]) != `[{"user":"hen","blocked":true}]` {
		t.Fatalf("blocked, contacts: %s", mustJSON(b.Data))
	}

	if ok, _ := env.mutate(t, danaPhone, "unblock", "hen"); ok != "true" {
		t.Fatal("unblock")
	}
	if r := henSocket.send(t, pb.Envelope_MESSAGE, "", dev(danaPhone)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("after unblocking: %v", r)
	}
	if ok, _ := env.mutate(t, henPhone, "unpair", "dana"); ok != "true" {
		t.Fatal("unpair")
	}
	if r := danaSocket.send(t, pb.Envelope_MESSAGE, "", dev(henPhone)); r.Status != pb.SendResult_NOT_PAIRED {
		t.Fatalf("after unpairing: %v", r)
	}
	if _, code := env.mutate(t, henPhone, "confirmPair", "dana"); code != "NO_PAIRING" {
		t.Fatalf("confirmPair without a new QR code: %s", code)
	}
}

// Revoking a phone closes its socket at once; senders must leave it out from then on, and its queue and keys go.
func TestARevokedDeviceIsCutOff(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana")
	henPhone, henTablet, danaPhone := env.phone(t, "hen"), env.phone(t, "hen"), env.phone(t, "dana")
	identity := ecKey()
	env.uploadKeys(t, henPhone, identity)
	env.uploadKeys(t, henTablet, identity)
	env.uploadKeys(t, danaPhone, ecKey())
	danaSocket, tabletSocket := env.socket(t, danaPhone), env.socket(t, henTablet)
	henSocket := env.socket(t, henPhone)
	env.pair(t, henPhone, []store.Device{dev(henPhone), dev(henTablet)}, danaPhone, danaSocket)
	tabletSocket.ws.Close(websocket.StatusNormalClosure, "")
	waitFor(t, func() bool { return !env.relay.Connected(dev(henTablet)) })
	tabletSocket = env.socket(t, henTablet) // with the pair request and PAIRED queued

	var data struct{ RevokeDevice adminDevice }
	if err := adminQuery(env.adminConfig, `mutation($s: String!) { revokeDevice(serial: $s) { serial } }`,
		map[string]any{"s": henTablet.serial}, &data); err != nil {
		t.Fatal(err)
	}
	if code := tabletSocket.closedWith(t); code != 4003 {
		t.Fatalf("the revoked tablet's socket closed with %d", code)
	}
	if n, _ := env.store.QueueLength(dev(henTablet)); n != 0 {
		t.Fatalf("the revoked tablet's queue holds %d", n)
	}
	if r := danaSocket.send(t, pb.Envelope_MESSAGE, "", dev(henPhone), dev(henTablet)); r.Status != pb.SendResult_STALE_DEVICES ||
		len(r.Devices[1].Devices) != 1 {
		t.Fatalf("a send to the revoked tablet: %v", r)
	}
	if r := danaSocket.send(t, pb.Envelope_MESSAGE, "", dev(henPhone)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("a send without it: %v", r)
	}
	if got, _ := env.bundles(t, danaPhone, "hen", ""); len(got.Devices) != 1 {
		t.Fatalf("bundles after revoking: %+v", got)
	}
	henSocket.next(t, "envelope")

	// Removing a user closes its sockets and forgets its contacts.
	var removed struct{ RemoveUser struct{ RevokedDevices int } }
	if err := adminQuery(env.adminConfig, `mutation { removeUser(name: "hen") { revokedDevices } }`, nil, &removed); err != nil {
		t.Fatal(err)
	}
	if code := henSocket.closedWith(t); code != 4003 {
		t.Fatalf("the removed user's socket closed with %d", code)
	}
	if env.book.Paired("hen", "dana") {
		t.Fatal("the removed user is still paired")
	}
	if r := danaSocket.send(t, pb.Envelope_MESSAGE, "", dev(henPhone)); r.Status != pb.SendResult_UNKNOWN_USER {
		t.Fatalf("a send to a removed user: %v", r)
	}
}

// One-time prekeys are used up one per fetch; then the Kyber last-resort key is given, and the count tells the
// phone to refill. Keys of the wrong size, or under another identity key, are refused.
func TestPrekeysAreUsedUpAndRefilled(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen")
	phone, tablet := env.phone(t, "hen"), env.phone(t, "hen")
	identity := ecKey()

	input := keysInput(identity, 7, 1, 2)
	delete(input, "signedPrekey")
	if r := env.graphql(t, phone.client, uploadMutation, map[string]any{"input": input}); errorCode(r) != "MISSING_KEYS" {
		t.Fatalf("a first upload without the signed prekey: %+v", r.Errors)
	}
	input = keysInput(identity, 7, 1, 2)
	input["oneTimePrekeys"] = []map[string]any{{"keyId": 1, "publicKey": b64(randomBytes(32))}}
	if r := env.graphql(t, phone.client, uploadMutation, map[string]any{"input": input}); errorCode(r) != "INVALID_KEY" {
		t.Fatalf("a 32-byte prekey: %+v", r.Errors)
	}
	input = keysInput(identity, 7, 1, 2)
	input["registrationId"] = 0
	if r := env.graphql(t, phone.client, uploadMutation, map[string]any{"input": input}); errorCode(r) != "INVALID_KEY" {
		t.Fatalf("registration id 0: %+v", r.Errors)
	}
	if me := env.graphql(t, phone.client, `{ me { identityKey } }`, nil); string(me.Data["me"]) != `{"identityKey":null}` {
		t.Fatalf("an identity key from refused uploads: %s", me.Data["me"])
	}
	r := env.graphql(t, phone.client, uploadMutation, map[string]any{"input": keysInput(identity, 7, 1, 2)})
	if string(r.Data["uploadPrekeys"]) != `{"oneTimePrekeys":2,"oneTimeKyberPrekeys":2,"refillBelow":20}` {
		t.Fatalf("upload: %s %+v", r.Data["uploadPrekeys"], r.Errors)
	}
	if me := env.graphql(t, phone.client, `{ me { identityKey } }`, nil); string(me.Data["me"]) != `{"identityKey":"`+b64(identity)+`"}` {
		t.Fatalf("me: %s", me.Data["me"])
	}
	// The tablet must use the user's identity key.
	if r := env.graphql(t, tablet.client, uploadMutation, map[string]any{"input": keysInput(ecKey(), 8, 1, 1)}); errorCode(r) != "IDENTITY_KEY_MISMATCH" {
		t.Fatalf("another identity key: %+v", r.Errors)
	}
	// The user's own tablet fetches the phone's bundles (multi-device): the tablet itself is left out.
	env.uploadKeys(t, tablet, identity)
	type fetched struct {
		prekey     int
		kyber      int
		lastResort bool
	}
	var got []fetched
	for range 3 {
		b, problem := env.bundles(t, tablet, "hen", "")
		if problem != "" || len(b.Devices) != 1 || b.Devices[0].DeviceNumber != 1 {
			t.Fatalf("bundles: %+v %s", b, problem)
		}
		f := fetched{prekey: -1, kyber: b.Devices[0].KyberPrekey.KeyID, lastResort: b.Devices[0].KyberPrekey.LastResort}
		if b.Devices[0].Prekey != nil {
			f.prekey = b.Devices[0].Prekey.KeyID
		}
		got = append(got, f)
	}
	if fmt.Sprint(got) != "[{1 1 false} {2 2 false} {-1 9999 true}]" {
		t.Fatalf("three fetches: %v", got)
	}
	count := env.graphql(t, phone.client, `{ prekeyCount { oneTimePrekeys oneTimeKyberPrekeys } }`, nil)
	if string(count.Data["prekeyCount"]) != `{"oneTimePrekeys":0,"oneTimeKyberPrekeys":0}` {
		t.Fatalf("prekeyCount: %s", count.Data["prekeyCount"])
	}
	// A refill keeps the signed prekey.
	refill := map[string]any{"identityKey": b64(identity), "registrationId": 7,
		"oneTimePrekeys": []map[string]any{{"keyId": 50, "publicKey": b64(ecKey())}}}
	if r := env.graphql(t, phone.client, uploadMutation, map[string]any{"input": refill}); string(r.Data["uploadPrekeys"]) !=
		`{"oneTimePrekeys":1,"oneTimeKyberPrekeys":0,"refillBelow":20}` {
		t.Fatalf("refill: %s %+v", r.Data["uploadPrekeys"], r.Errors)
	}
	if b, _ := env.bundles(t, tablet, "hen", ""); b.Devices[0].Prekey.KeyID != 50 || b.Devices[0].SignedPrekey.KeyID != 1 {
		t.Fatalf("after the refill: %+v", b)
	}
	// The devices of the user, as a phone lists them.
	d := env.graphql(t, tablet.client, `{ devices { deviceNumber name registrationId current } }`, nil)
	if string(d.Data["devices"]) != `[{"deviceNumber":1,"name":"Pixel 9 Pro","registrationId":7,"current":false},`+
		`{"deviceNumber":2,"name":"Pixel 9 Pro","registrationId":1002,"current":true}]` {
		t.Fatalf("devices: %s %+v", d.Data["devices"], d.Errors)
	}
}

// Linking a second phone: it enrolls, an existing phone sends it a PROVISIONING envelope (sealed to the key in its
// QR code), and it then uploads keys under the same identity key.
func TestLinkingASecondPhone(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen")
	phone := env.phone(t, "hen")
	identity := ecKey()
	env.uploadKeys(t, phone, identity)
	phoneSocket := env.socket(t, phone)
	linked := env.phone(t, "hen")
	linkedSocket := env.socket(t, linked)

	// The new phone has no keys yet, so a message to the user's devices leaves it out; provisioning reaches it.
	r := phoneSocket.send(t, pb.Envelope_PROVISIONING, "", dev(linked))
	if r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("provisioning: %v", r)
	}
	if e := linkedSocket.envelope(t); e.Type != pb.Envelope_PROVISIONING || e.SenderDevice != 1 {
		t.Fatalf("the linked phone got %v", e)
	}
	if r := phoneSocket.send(t, pb.Envelope_PROVISIONING, "", store.Device{User: "hen", Number: 9}); r.Status != pb.SendResult_UNKNOWN_USER {
		t.Fatalf("provisioning to no device: %v", r)
	}
	env.uploadKeys(t, linked, identity)
	if r := phoneSocket.send(t, pb.Envelope_MESSAGE, "", dev(linked)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("a sync to the linked phone: %v", r)
	}
	linkedSocket.envelope(t)
}

// A phone makes the code for its user's next phone itself (createLinkCode): the new phone enrolls with it as the same
// user, and before it has keys it can ask the old phone for them with a PROVISIONING envelope. A phone of another
// user can't link into this one, and only 3 codes wait at once.
func TestAPhoneMakesTheCodeToLinkAnother(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana")
	old := env.phone(t, "hen")
	env.uploadKeys(t, old, ecKey())
	phoneSocket := env.socket(t, old)

	r := env.graphql(t, old.client, `mutation { createLinkCode { code expiresAt } }`, nil)
	var link struct{ Code, ExpiresAt string }
	if err := json.Unmarshal(r.Data["createLinkCode"], &link); err != nil || link.Code == "" || len(r.Errors) > 0 {
		t.Fatalf("createLinkCode: %s %+v", r.Data["createLinkCode"], r.Errors)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enrolled := env.enroll(t, link.Code, key)
	if enrolled.Typename != "EnrolledDevice" || enrolled.User != "hen" || enrolled.DeviceNumber != 2 {
		t.Fatalf("enrolling with the link code: %+v", enrolled)
	}
	if again := env.enroll(t, link.Code, key); again.Typename == "EnrolledDevice" {
		t.Fatalf("a link code worked twice")
	}
	der, _ := base64.StdEncoding.DecodeString(enrolled.Certificate)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	linked := &phone{user: "hen", number: enrolled.DeviceNumber, client: env.client(&cert), cert: cert}
	linkedSocket := env.socket(t, linked)

	// The new phone has no keys and no sessions: its request goes to the old phone as PROVISIONING, and the answer back.
	if r := linkedSocket.send(t, pb.Envelope_PROVISIONING, "", dev(old)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("the new phone's request: %v", r)
	}
	if e := phoneSocket.envelope(t); e.Type != pb.Envelope_PROVISIONING || e.SenderDevice != 2 || e.SenderUser != "hen" {
		t.Fatalf("the old phone got %v", e)
	}
	if r := phoneSocket.send(t, pb.Envelope_PROVISIONING, "", dev(linked)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("the old phone's answer: %v", r)
	}
	if e := linkedSocket.envelope(t); e.Type != pb.Envelope_PROVISIONING || e.SenderDevice != 1 {
		t.Fatalf("the new phone got %v", e)
	}

	dana := env.phone(t, "dana")
	danaSocket := env.socket(t, dana)
	if r := danaSocket.send(t, pb.Envelope_PROVISIONING, "", dev(old)); r.Status != pb.SendResult_INVALID {
		t.Fatalf("provisioning from another user: %v", r)
	}

	for i := 0; i < 2; i++ {
		if r := env.graphql(t, old.client, `mutation { createLinkCode { code } }`, nil); len(r.Errors) > 0 {
			t.Fatalf("code %d: %+v", i+2, r.Errors)
		}
	}
	if code := errorCode(env.graphql(t, linked.client, `mutation { createLinkCode { code } }`, nil)); code != "" {
		t.Fatalf("the used code still counted: %s", code)
	}
	if code := errorCode(env.graphql(t, old.client, `mutation { createLinkCode { code } }`, nil)); code != "RATE_LIMITED" {
		t.Fatalf("a fourth waiting code: %q", code)
	}
}

// After every phone was lost, the user's new phone replaces the identity key, once the old phones are revoked, and
// every contact hears of it.
func TestReplacingTheIdentityKey(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana")
	lost, danaPhone := env.phone(t, "hen"), env.phone(t, "dana")
	env.uploadKeys(t, lost, ecKey())
	env.uploadKeys(t, danaPhone, ecKey())
	danaSocket := env.socket(t, danaPhone)
	env.pair(t, lost, []store.Device{dev(lost)}, danaPhone, danaSocket)
	danaSocket.envelope(t) // PAIRED

	fresh := env.phone(t, "hen")
	newKey := ecKey()
	replace := `mutation($k: String!) { replaceIdentityKey(identityKey: $k) }`
	if r := env.graphql(t, fresh.client, replace, map[string]any{"k": b64(newKey)}); errorCode(r) != "OTHER_DEVICES_ACTIVE" {
		t.Fatalf("with the lost phone still active: %+v", r.Errors)
	}
	if err := adminQuery(env.adminConfig, `mutation($s: String!) { revokeDevice(serial: $s) { serial } }`,
		map[string]any{"s": lost.serial}, &struct{}{}); err != nil {
		t.Fatal(err)
	}
	if r := env.graphql(t, fresh.client, replace, map[string]any{"k": b64(newKey)}); string(r.Data["replaceIdentityKey"]) != "true" {
		t.Fatalf("replaceIdentityKey: %+v", r)
	}
	e := danaSocket.envelope(t)
	if e.Type != pb.Envelope_IDENTITY_KEY_CHANGED || e.SenderUser != "hen" || !bytes.Equal(e.Ciphertext, newKey) {
		t.Fatalf("dana got %v", e)
	}
	env.uploadKeys(t, fresh, newKey)
}

// An envelope no device takes is deleted after queue_days.
func TestTheQueueExpires(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen")
	phone, tablet := env.phone(t, "hen"), env.phone(t, "hen")
	identity := ecKey()
	env.uploadKeys(t, phone, identity)
	env.uploadKeys(t, tablet, identity)
	if r := env.socket(t, phone).send(t, pb.Envelope_MESSAGE, "", dev(tablet)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("send: %v", r)
	}
	env.relay.Sweep()
	if n, _ := env.store.QueueLength(dev(tablet)); n != 1 {
		t.Fatalf("queued: %d", n)
	}
	env.relay.Now = func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
	env.relay.Sweep()
	env.relay.Now = time.Now
	if n, _ := env.store.QueueLength(dev(tablet)); n != 0 {
		t.Fatalf("after 31 days: %d", n)
	}
}

// /ws needs an enrolled device's certificate.
func TestTheSocketNeedsACertificate(t *testing.T) {
	env := newTestEnv(t)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: env.roots, NextProtos: []string{"http/1.1"}}}}
	_, resp, err := websocket.Dial(context.Background(), "wss"+strings.TrimPrefix(env.public.URL, "https")+"/ws",
		&websocket.DialOptions{HTTPClient: client})
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/ws without a certificate: %v %v", err, resp)
	}
}
