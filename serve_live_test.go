package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/chencohensolutions/push-to-talk-server-go/livekit"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/recorder"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
	lksdk "github.com/livekit/server-sdk-go/v2"
)

// fakeLiveKit stands in for livekit-server's HTTP side: /rtc (signalling, answered plainly here) and the room API,
// recording what ptt-server asked.
type fakeLiveKit struct {
	*httptest.Server
	keys    livekit.Keys
	mu      sync.Mutex
	rtc     []string // paths and queries that reached /rtc
	removed []string // "room identity"
	created []string // "room max_participants"
}

func newFakeLiveKit(t *testing.T) *fakeLiveKit {
	f := &fakeLiveKit{keys: livekit.NewKeys()}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/rtc"):
			f.rtc = append(f.rtc, r.URL.RequestURI())
			io.WriteString(w, "livekit signalling")
		case r.URL.Path == "/twirp/livekit.RoomService/RemoveParticipant":
			if !f.validToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
				http.Error(w, `{"code":"unauthenticated"}`, http.StatusUnauthorized)
				return
			}
			var in struct{ Room, Identity string }
			json.NewDecoder(r.Body).Decode(&in)
			f.removed = append(f.removed, in.Room+" "+in.Identity)
			io.WriteString(w, "{}")
		case r.URL.Path == "/twirp/livekit.RoomService/CreateRoom":
			if !f.validToken(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
				http.Error(w, `{"code":"unauthenticated"}`, http.StatusUnauthorized)
				return
			}
			var in struct {
				Name            string
				MaxParticipants int `json:"max_participants"`
			}
			json.NewDecoder(r.Body).Decode(&in)
			f.created = append(f.created, fmt.Sprintf("%s %d", in.Name, in.MaxParticipants))
			io.WriteString(w, "{}")
		default:
			http.Error(w, `{"code":"not_found"}`, http.StatusNotFound)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

// validToken checks a token's HS256 signature with the fake's secret.
func (f *fakeLiveKit) validToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(f.keys.Secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) == parts[2]
}

func (f *fakeLiveKit) removals() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.removed...)
}

func newLiveEnv(t *testing.T) (*testEnv, *fakeLiveKit) {
	t.Helper()
	fake := newFakeLiveKit(t)
	keysFile := filepath.Join(t.TempDir(), "livekit.keys")
	os.WriteFile(keysFile, []byte(fake.keys.Key+": "+fake.keys.Secret+"\n"), 0o600)
	env := newTestEnv(t, func(c *auth.AppConfig) {
		c.LiveKit = &auth.LiveKitConfig{Binary: "none", KeysFile: keysFile, ConfigFile: "livekit.yaml", URL: fake.URL,
			TCPPort: 7881, UDPPort: 7882}
	})
	return env, fake
}

// Phase 5b from the server's side: a phone gets a room token for a conversation it may talk in, LiveKit's
// signalling is reached only through /rtc with a certificate, and a member taken out of a group is taken out of its
// room.
func TestLiveTalkTokensAndRooms(t *testing.T) {
	env, fake := newLiveEnv(t)
	env.addUsers(t, "hen", "dana", "eli")
	hen, dana, eli := env.phone(t, "hen"), env.phone(t, "dana"), env.phone(t, "eli")
	env.uploadKeys(t, hen, ecKey())
	env.uploadKeys(t, dana, ecKey())
	henSocket := env.socket(t, hen)
	env.pair(t, dana, []store.Device{dev(dana)}, hen, henSocket)

	if r := env.graphql(t, hen.client, `{ serverInfo { liveTalk } }`, nil); string(r.Data["serverInfo"]) != `{"liveTalk":true}` {
		t.Fatalf("serverInfo.liveTalk: %s", r.Data["serverInfo"])
	}
	const tokenMutation = `mutation($p: String, $g: ID) { talkToken(peer: $p, group: $g) { token room identity path expiresAt } }`
	r := env.graphql(t, hen.client, tokenMutation, map[string]any{"p": "dana"})
	var got struct{ Token, Room, Identity, Path string }
	json.Unmarshal(r.Data["talkToken"], &got)
	if len(r.Errors) > 0 || got.Room != livekit.PairRoom("hen", "dana") || got.Identity != livekit.Identity("hen", hen.number) ||
		got.Path != "/rtc" || !fake.validToken(got.Token) {
		t.Fatalf("talkToken: %s %+v", r.Data["talkToken"], r.Errors)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(got.Token, ".")[1])
	var claims struct {
		Iss, Sub string
		Exp      int64
		Video    livekit.Grant
	}
	json.Unmarshal(payload, &claims)
	if claims.Iss != fake.keys.Key || claims.Sub != got.Identity || claims.Video.Room != got.Room || !claims.Video.RoomJoin ||
		claims.Video.RoomAdmin || claims.Video.CanPublishData == nil || *claims.Video.CanPublishData ||
		time.Until(time.Unix(claims.Exp, 0)) > livekit.TokenTTL {
		t.Fatalf("the token's claims: %s", payload)
	}
	if r := env.graphql(t, eli.client, tokenMutation, map[string]any{"p": "hen"}); errorCode(r) != "NOT_PAIRED" {
		t.Fatalf("talkToken for someone not a contact: %s", errorCode(r))
	}
	if r := env.graphql(t, hen.client, tokenMutation, map[string]any{}); errorCode(r) != "INVALID" {
		t.Fatalf("talkToken naming nothing: %s", errorCode(r))
	}

	// /rtc goes to LiveKit for an enrolled device, and not without a certificate.
	resp, err := hen.client.Get(env.public.URL + "/rtc/validate?access_token=" + got.Token)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "livekit signalling" {
		t.Fatalf("/rtc: %d %s", resp.StatusCode, body)
	}
	if resp, err := env.client(nil).Get(env.public.URL + "/rtc/validate"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("/rtc without a certificate reached LiveKit")
		}
	}

	// Taken out of a group: out of its room at once.
	g := env.createGroup(t, hen)
	env.groupOp(t, hen, "inviteToGroup", g.ID, "dana")
	env.groupOp(t, dana, "acceptGroupInvite", g.ID, "")
	if r := env.graphql(t, dana.client, tokenMutation, map[string]any{"g": g.ID}); errorCode(r) != "" {
		t.Fatalf("talkToken for a group: %s", errorCode(r))
	}
	env.groupOp(t, hen, "removeFromGroup", g.ID, "dana")
	want := livekit.GroupRoom(g.ID) + " " + livekit.Identity("dana", dana.number)
	waitFor(t, func() bool {
		for _, r := range fake.removals() {
			if r == want {
				return true
			}
		}
		return false
	})
	if r := env.graphql(t, dana.client, tokenMutation, map[string]any{"g": g.ID}); errorCode(r) != "NOT_MEMBER" {
		t.Fatalf("talkToken after being taken out: %s", errorCode(r))
	}
}

// Without "livekit" in config.json there is no live path: talkToken says so, and /rtc isn't served.
func TestNoLiveKitNoLiveTalk(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana")
	hen := env.phone(t, "hen")
	if r := env.graphql(t, hen.client, `mutation { talkToken(peer: "dana") { token } }`, nil); errorCode(r) != "LIVE_OFF" {
		t.Fatalf("talkToken without LiveKit: %s", errorCode(r))
	}
	resp, err := hen.client.Get(env.public.URL + "/rtc/validate")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatal("/rtc answered without LiveKit")
	}
}

// Phase 6 from the server's side: a call has its own room, made with a cap of livekit.max_call_devices (32), bound to its conversation; blocking
// takes the other side out of it.
func TestCallTokens(t *testing.T) {
	env, fake := newLiveEnv(t)
	env.addUsers(t, "hen", "dana", "eli")
	hen, dana, eli := env.phone(t, "hen"), env.phone(t, "dana"), env.phone(t, "eli")
	for _, p := range []*phone{hen, dana, eli} {
		env.uploadKeys(t, p, ecKey())
	}
	henSocket := env.socket(t, hen)
	env.pair(t, dana, []store.Device{dev(dana)}, hen, henSocket)
	env.pair(t, eli, []store.Device{dev(eli)}, hen, henSocket)

	const callMutation = `mutation($c: ID!, $p: String, $g: ID) { callToken(call: $c, peer: $p, group: $g) { token room identity } }`
	id := burstID()
	call := func(p *phone, peer string) (string, string) {
		r := env.graphql(t, p.client, callMutation, map[string]any{"c": id, "p": peer})
		var got struct{ Room, Token string }
		json.Unmarshal(r.Data["callToken"], &got)
		if errorCode(r) == "" && !fake.validToken(got.Token) {
			t.Fatalf("callToken's token doesn't verify: %s", r.Data["callToken"])
		}
		return got.Room, errorCode(r)
	}
	if room, code := call(hen, "dana"); code != "" || room != livekit.CallRoom(id) {
		t.Fatalf("callToken: %s %s", room, code)
	}
	fake.mu.Lock()
	created := append([]string{}, fake.created...)
	fake.mu.Unlock()
	if len(created) != 1 || created[0] != livekit.CallRoom(id)+" 33" { // 32 devices + the hidden recorder
		t.Fatalf("the call's room: %v", created)
	}
	if room, code := call(dana, "hen"); code != "" || room != livekit.CallRoom(id) {
		t.Fatalf("callToken for the one called: %s %s", room, code)
	}
	if _, code := call(eli, "hen"); code != "INVALID" {
		t.Fatalf("the call id from another conversation: %s", code)
	}
	if r := env.graphql(t, hen.client, callMutation, map[string]any{"c": "short", "p": "dana"}); errorCode(r) != "INVALID" {
		t.Fatalf("a bad call id: %s", errorCode(r))
	}
	env.mutate(t, dana, "block", "hen")
	want := livekit.CallRoom(id) + " " + livekit.Identity("hen", hen.number)
	waitFor(t, func() bool {
		for _, r := range fake.removals() {
			if r == want {
				return true
			}
		}
		return false
	})
	if _, code := call(hen, "dana"); code != "BLOCKED" {
		t.Fatalf("callToken after a block: %s", code)
	}
}

// `ptt-server livekit update` ends with restartLiveKit: false when this server runs no LiveKit, and a restart asked of
// livekit.Run when it does.
func TestRestartLiveKit(t *testing.T) {
	env, _ := newLiveEnv(t) // binary "none": LiveKit runs some other way
	var data struct{ RestartLiveKit bool }
	if err := adminQuery(env.adminConfig, `mutation { restartLiveKit }`, nil, &data); err != nil || data.RestartLiveKit {
		t.Fatalf("restartLiveKit without a LiveKit the server runs: %v %v", data, err)
	}
	env.liveRestart = make(chan struct{}, 1)
	for range 2 { // a second ask while one waits is no error
		if err := adminQuery(env.adminConfig, `mutation { restartLiveKit }`, nil, &data); err != nil || !data.RestartLiveKit {
			t.Fatalf("restartLiveKit: %v %v", data, err)
		}
	}
	select {
	case <-env.liveRestart:
	default:
		t.Fatal("no restart was asked of LiveKit")
	}
	if _, err := liveKitProgram(env.config); err == nil {
		t.Fatal(`livekit update with binary "none"`)
	}
}

// fakeRoom stands in for a LiveKit room the recorder joined, with a set number of others in it.
type fakeRoom struct {
	others     int
	disconnect func()
}

func (r *fakeRoom) Disconnect() {
	if r.disconnect != nil {
		r.disconnect()
	}
}
func (r *fakeRoom) RemoteParticipantCount() int { return r.others }

// Every call is kept (2026-11-22, hen): callToken starts the recorder keeping the call, callRecording lists its
// tracks to whoever may read them, and GET /blob reads a track. The recorder never fails a call.
func TestCallsAreKept(t *testing.T) {
	env, _ := newLiveEnv(t)
	if !env.config.LiveKit.KeepsCalls() || env.recorder == nil {
		t.Fatal("a LiveKit server keeps calls by default")
	}
	// The recorder joins through this fake instead of a real LiveKit, and lets the test see the room it joined.
	joined := make(chan *fakeRoom, 4)
	env.recorder.Join = func(url, token string, cb *lksdk.RoomCallback) (recorder.Room, error) {
		room := &fakeRoom{others: 1}
		joined <- room
		return room, nil
	}

	env.addUsers(t, "hen", "dana", "eli")
	hen, dana, eli := env.phone(t, "hen"), env.phone(t, "dana"), env.phone(t, "eli")
	for _, p := range []*phone{hen, dana, eli} {
		env.uploadKeys(t, p, ecKey())
	}
	henSocket := env.socket(t, hen)
	env.pair(t, dana, []store.Device{dev(dana)}, hen, henSocket)

	const callMutation = `mutation($c: ID!, $p: String, $g: ID) { callToken(call: $c, peer: $p, group: $g) { room } }`
	id := burstID()
	if r := env.graphql(t, hen.client, callMutation, map[string]any{"c": id, "p": "dana"}); errorCode(r) != "" {
		t.Fatalf("callToken: %s", errorCode(r))
	}
	select {
	case <-joined:
	case <-time.After(2 * time.Second):
		t.Fatal("the recorder didn't join the call's room")
	}

	// A track of the call, as the recorder would write it (its frames stay encrypted; the test writes bytes).
	blob := burstID()
	if err := env.recorder.Blobs.Create(blobs.Meta{ID: blob, Kind: blobs.Track, Owner: "hen", Peer: "dana",
		Track: &blobs.TrackInfo{Call: id, Identity: "hen.1", Media: "audio", Codec: "audio/opus"}}); err != nil {
		t.Fatal(err)
	}
	env.recorder.Blobs.AppendRecord(blob, []byte("frame"), true)

	const recQuery = `query($c: ID!, $p: String) { callRecording(call: $c, peer: $p) { call recording tracks { blob identity kind codec } } }`
	r := env.graphql(t, hen.client, recQuery, map[string]any{"c": id, "p": "dana"})
	var got struct {
		Recording bool
		Tracks    []struct{ Blob, Identity, Kind, Codec string }
	}
	json.Unmarshal(r.Data["callRecording"], &got)
	if !got.Recording || len(got.Tracks) != 1 || got.Tracks[0].Blob != blob || got.Tracks[0].Identity != "hen.1" ||
		got.Tracks[0].Kind != "audio" || got.Tracks[0].Codec != "audio/opus" {
		t.Fatalf("callRecording for hen: %s", r.Data["callRecording"])
	}
	// dana, the other side, sees it too; eli, not in the conversation, can't even get a token.
	if r := env.graphql(t, dana.client, recQuery, map[string]any{"c": id, "p": "hen"}); errorCode(r) != "" {
		t.Fatalf("callRecording for dana: %s", errorCode(r))
	}
	if r := env.graphql(t, eli.client, recQuery, map[string]any{"c": id, "p": "hen"}); errorCode(r) != "NOT_PAIRED" {
		t.Fatalf("callRecording for eli (not a contact): %s", errorCode(r))
	}
	// The track reads back over /blob for a reader, and is kept past the blob lifetime.
	resp, body := env.blobRequest(t, hen, "GET", blob, nil, nil)
	if resp.StatusCode != 200 || len(body) == 0 {
		t.Fatalf("GET the track: %d", resp.StatusCode)
	}
	if n := env.relay.Blobs.Expire(time.Now().Add(365 * 24 * time.Hour)); n != 0 {
		t.Fatalf("a kept call's track expired: %d", n)
	}

	// serverInfo says calls are kept.
	if r := env.graphql(t, hen.client, `{ serverInfo { keepsCalls } }`, nil); string(r.Data["serverInfo"]) != `{"keepsCalls":true}` {
		t.Fatalf("serverInfo.keepsCalls: %s", r.Data["serverInfo"])
	}
}

// 2026-11-22 (hen): one-to-one calls and talk are for contacts only, and a kept call is only for the people who were
// in it. dana and eli share hen's group but aren't contacts: they still exchange one-to-one messages (the group's
// sender keys travel that way) but can't call or talk to each other one to one, and only those who joined a group
// call may list and download its tracks.
func TestCallsAreForContactsAndKeptCallsForThoseInThem(t *testing.T) {
	env, _ := newLiveEnv(t)
	env.recorder.Join = func(url, token string, cb *lksdk.RoomCallback) (recorder.Room, error) {
		return &fakeRoom{others: 1}, nil
	}
	env.addUsers(t, "hen", "dana", "eli")
	hen, dana, eli := env.phone(t, "hen"), env.phone(t, "dana"), env.phone(t, "eli")
	for _, p := range []*phone{hen, dana, eli} {
		env.uploadKeys(t, p, ecKey())
	}
	henSocket, danaSocket := env.socket(t, hen), env.socket(t, dana)
	env.pair(t, dana, []store.Device{dev(dana)}, hen, henSocket)
	env.pair(t, eli, []store.Device{dev(eli)}, hen, henSocket)
	g := env.createGroup(t, hen)
	for _, p := range []*phone{dana, eli} {
		if _, code := env.groupOp(t, hen, "inviteToGroup", g.ID, p.user); code != "" {
			t.Fatalf("invite %s: %s", p.user, code)
		}
		if _, code := env.groupOp(t, p, "acceptGroupInvite", g.ID, ""); code != "" {
			t.Fatalf("%s accepting: %s", p.user, code)
		}
	}

	// A one-to-one message between the two group members goes through; a call invite doesn't.
	if r := danaSocket.send(t, pb.Envelope_PREKEY_MESSAGE, "", dev(eli)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("a message to a group member: %v %s", r.Status, r.Detail)
	}
	invite := &pb.Send{ClientId: "call-invite", PushKind: pb.PushKind_PUSH_CALL, Envelopes: []*pb.Envelope{{
		RecipientUser: "eli", RecipientDevice: uint32(eli.number), Type: pb.Envelope_MESSAGE, Ciphertext: []byte("invite")}}}
	danaSocket.write(t, &pb.Frame{Kind: &pb.Frame_Send{Send: invite}})
	if r := danaSocket.next(t, "send_result").GetSendResult(); r.Status != pb.SendResult_NOT_PAIRED {
		t.Fatalf("a call invite to a group member who isn't a contact: %v", r.Status)
	}
	const callMutation = `mutation($c: ID!, $p: String, $g: ID) { callToken(call: $c, peer: $p, group: $g) { room } }`
	if r := env.graphql(t, dana.client, callMutation, map[string]any{"c": burstID(), "p": "eli"}); errorCode(r) != "NOT_PAIRED" {
		t.Fatalf("callToken to a group member who isn't a contact: %s", errorCode(r))
	}
	if r := env.graphql(t, dana.client, `mutation { talkToken(peer: "eli") { token } }`, nil); errorCode(r) != "NOT_PAIRED" {
		t.Fatalf("talkToken to a group member who isn't a contact: %s", errorCode(r))
	}
	// A contact may still call one to one.
	if r := env.graphql(t, dana.client, callMutation, map[string]any{"c": burstID(), "p": "hen"}); errorCode(r) != "" {
		t.Fatalf("callToken to a contact: %s", errorCode(r))
	}

	// A group call that hen and dana joined; eli is in the group but stayed out.
	id := burstID()
	if r := env.graphql(t, hen.client, callMutation, map[string]any{"c": id, "g": g.ID}); errorCode(r) != "" {
		t.Fatalf("group callToken: %s", errorCode(r))
	}
	var tracks []string
	for _, identity := range []string{"hen.1", "dana.1"} {
		blob := burstID()
		if err := env.recorder.Blobs.Create(blobs.Meta{ID: blob, Kind: blobs.Track, Owner: "hen", Group: g.ID,
			Track: &blobs.TrackInfo{Call: id, Identity: identity, Media: "audio", Codec: "audio/opus"}}); err != nil {
			t.Fatal(err)
		}
		env.recorder.Blobs.AppendRecord(blob, []byte("frame"), true)
		tracks = append(tracks, blob)
	}
	const recQuery = `query($c: ID!, $g: ID) { callRecording(call: $c, group: $g) { tracks { blob } } }`
	count := func(p *phone) int {
		r := env.graphql(t, p.client, recQuery, map[string]any{"c": id, "g": g.ID})
		if errorCode(r) != "" {
			t.Fatalf("callRecording for %s: %s", p.user, errorCode(r))
		}
		var got struct{ Tracks []struct{ Blob string } }
		json.Unmarshal(r.Data["callRecording"], &got)
		return len(got.Tracks)
	}
	if count(hen) != 2 || count(dana) != 2 || count(eli) != 0 {
		t.Fatalf("tracks listed: hen %d, dana %d, eli %d", count(hen), count(dana), count(eli))
	}
	if resp, _ := env.blobRequest(t, dana, "GET", tracks[0], nil, nil); resp.StatusCode != 200 {
		t.Fatalf("dana, in the call, reading a track: %d", resp.StatusCode)
	}
	if resp, _ := env.blobRequest(t, eli, "GET", tracks[0], nil, nil); resp.StatusCode != 403 && resp.StatusCode != 404 {
		t.Fatalf("eli, not in the call, reading a track: %d", resp.StatusCode)
	}
}
