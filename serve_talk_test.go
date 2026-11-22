package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/relay"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
	"google.golang.org/protobuf/proto"
)

func burstID() string {
	raw := make([]byte, 16)
	rand.Read(raw)
	return hex.EncodeToString(raw)
}

// talkState is the next TalkState frame.
func (s *socket) talkState(t *testing.T) *pb.TalkState {
	t.Helper()
	return s.next(t, "talk_state").GetTalkState()
}

// segmentFrame is the next ClipSegment frame.
func (s *socket) segmentFrame(t *testing.T) *pb.ClipSegment {
	t.Helper()
	return s.next(t, "clip_segment").GetClipSegment()
}

func (s *socket) talk(t *testing.T, id, peer, group string) *pb.TalkState {
	t.Helper()
	s.write(t, &pb.Frame{Kind: &pb.Frame_TalkStart{TalkStart: &pb.TalkStart{BurstId: id, Peer: peer, Group: group}}})
	return s.talkState(t)
}

func (s *socket) segment(t *testing.T, id string, index uint32, last bool) {
	t.Helper()
	s.write(t, &pb.Frame{Kind: &pb.Frame_ClipSegment{ClipSegment: &pb.ClipSegment{BurstId: id, Index: index, Last: last,
		Ciphertext: []byte(fmt.Sprintf("segment %d", index))}}})
}

// blobRequest sends method to /blob/<id> as p, with headers and body.
func (e *testEnv) blobRequest(t *testing.T, p *phone, method, path string, headers map[string]string, body []byte) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.public.URL+"/blob/"+path, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

// records reads a clip's records.
func records(t *testing.T, data []byte) []*pb.ClipSegment {
	t.Helper()
	var out []*pb.ClipSegment
	for len(data) > 0 {
		if len(data) < 4 {
			t.Fatalf("a clip ends inside a length")
		}
		n := binary.BigEndian.Uint32(data)
		var seg pb.ClipSegment
		if err := proto.Unmarshal(data[4:4+n], &seg); err != nil {
			t.Fatal(err)
		}
		out = append(out, &seg)
		data = data[4+n:]
	}
	return out
}

// Phase 5a from the server's side: a talker takes the floor of a conversation, the other side is told and gets the
// segments live, a second talker meanwhile is busy, and the clip can be read back over /blob, also while it grows.
func TestTalkInAConversation(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana", "eli")
	hen, dana, eli := env.phone(t, "hen"), env.phone(t, "dana"), env.phone(t, "eli")
	for _, p := range []*phone{hen, dana, eli} {
		env.uploadKeys(t, p, ecKey())
	}
	henSocket, danaSocket, eliSocket := env.socket(t, hen), env.socket(t, dana), env.socket(t, eli)
	env.pair(t, dana, []store.Device{dev(dana)}, hen, henSocket)
	danaSocket.envelopeOf(t, pb.Envelope_PAIRED)

	if s := eliSocket.talk(t, burstID(), "hen", ""); s.Event != pb.TalkState_REFUSED || s.Refusal != pb.SendResult_NOT_PAIRED {
		t.Fatalf("talk to someone not a contact: %v", s)
	}
	if s := henSocket.talk(t, "short", "dana", ""); s.Event != pb.TalkState_REFUSED || s.Refusal != pb.SendResult_INVALID {
		t.Fatalf("a bad burst id: %v", s)
	}

	id := burstID()
	if s := henSocket.talk(t, id, "dana", ""); s.Event != pb.TalkState_GRANTED || s.StartedAt == 0 {
		t.Fatalf("talk: %v", s)
	}
	started := danaSocket.talkState(t)
	if started.Event != pb.TalkState_STARTED || started.BurstId != id || started.TalkerUser != "hen" || started.Peer != "hen" {
		t.Fatalf("the listener's STARTED: %v", started)
	}
	danaSocket.write(t, &pb.Frame{Kind: &pb.Frame_TalkAck{TalkAck: &pb.TalkAck{BurstId: id}}})
	if s := danaSocket.talk(t, burstID(), "hen", ""); s.Event != pb.TalkState_BUSY || s.TalkerUser != "hen" {
		t.Fatalf("talking over hen: %v", s)
	}

	// A reader that follows the clip while it grows.
	follow := make(chan []byte, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, env.public.URL+"/blob/"+id, nil)
		resp, err := dana.client.Do(req)
		if err != nil {
			follow <- nil
			return
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		follow <- data
	}()

	henSocket.segment(t, id, 0, false)
	if seg := danaSocket.segmentFrame(t); seg.Index != 0 || string(seg.Ciphertext) != "segment 0" || seg.BurstId != id {
		t.Fatalf("the first segment, live: %v", seg)
	}
	henSocket.segment(t, id, 5, false)
	if s := henSocket.talkState(t); s.Event != pb.TalkState_REFUSED {
		t.Fatalf("a segment out of order: %v", s)
	}
	danaSocket.segment(t, id, 1, false)
	if s := danaSocket.talkState(t); s.Event != pb.TalkState_REFUSED {
		t.Fatalf("a segment from a listener: %v", s)
	}
	henSocket.segment(t, id, 1, false)
	danaSocket.segmentFrame(t)
	henSocket.segment(t, id, 2, true)
	if seg := danaSocket.segmentFrame(t); seg.Index != 2 || !seg.Last {
		t.Fatalf("the last segment, live: %v", seg)
	}
	if s := danaSocket.talkState(t); s.Event != pb.TalkState_ENDED || s.EndReason != pb.TalkState_RELEASED {
		t.Fatalf("the listener's ENDED: %v", s)
	}
	if s := henSocket.talkState(t); s.Event != pb.TalkState_ENDED {
		t.Fatalf("the talker's ENDED: %v", s)
	}
	select {
	case data := <-follow:
		if got := records(t, data); len(got) != 3 || !got[2].Last || string(got[1].Ciphertext) != "segment 1" {
			t.Fatalf("the clip, followed: %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the following reader didn't end with the clip")
	}

	// Read back later, from an offset, and only by the conversation.
	resp, data := env.blobRequest(t, dana, http.MethodGet, id, nil, nil)
	if resp.StatusCode != 200 || len(records(t, data)) != 3 || resp.Header.Get(relay.HeaderComplete) != "true" {
		t.Fatalf("GET the clip: %d %d", resp.StatusCode, len(data))
	}
	first := 4 + int(binary.BigEndian.Uint32(data))
	resp, rest := env.blobRequest(t, dana, http.MethodGet, id, map[string]string{"Range": fmt.Sprintf("bytes=%d-", first)}, nil)
	if resp.StatusCode != http.StatusPartialContent || len(records(t, rest)) != 2 {
		t.Fatalf("GET the clip from its second record: %d", resp.StatusCode)
	}
	if resp, _ := env.blobRequest(t, eli, http.MethodGet, id, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET by someone outside the conversation: %d", resp.StatusCode)
	}

	// The floor is free again; a burst whose talker drops ends after a moment.
	second := burstID()
	if s := danaSocket.talk(t, second, "hen", ""); s.Event != pb.TalkState_GRANTED {
		t.Fatalf("talk after the floor was let go: %v", s)
	}
	henSocket.talkState(t) // STARTED
	danaSocket.ws.CloseNow()
	if s := henSocket.talkState(t); s.Event != pb.TalkState_ENDED || s.EndReason != pb.TalkState_DROPPED || s.BurstId != second {
		t.Fatalf("a burst whose talker dropped: %v", s)
	}
}

// A group burst reaches every member's connected devices.
func TestTalkInAGroup(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana", "noa")
	hen, dana, noa := env.phone(t, "hen"), env.phone(t, "dana"), env.phone(t, "noa")
	for _, p := range []*phone{hen, dana, noa} {
		env.uploadKeys(t, p, ecKey())
	}
	henSocket, danaSocket, noaSocket := env.socket(t, hen), env.socket(t, dana), env.socket(t, noa)
	env.pair(t, dana, []store.Device{dev(dana)}, hen, henSocket)
	env.pair(t, noa, []store.Device{dev(noa)}, hen, henSocket)
	g := env.createGroup(t, hen)
	for _, p := range []*phone{dana, noa} {
		env.groupOp(t, hen, "inviteToGroup", g.ID, p.user)
		env.groupOp(t, p, "acceptGroupInvite", g.ID, "")
	}
	id := burstID()
	if s := danaSocket.talk(t, id, "", g.ID); s.Event != pb.TalkState_GRANTED {
		t.Fatalf("talk in the group: %v", s)
	}
	for _, s := range []*socket{henSocket, noaSocket} {
		if st := s.talkState(t); st.Event != pb.TalkState_STARTED || st.Group != g.ID || st.TalkerUser != "dana" {
			t.Fatalf("a member's STARTED: %v", st)
		}
	}
	danaSocket.write(t, &pb.Frame{Kind: &pb.Frame_TalkEnd{TalkEnd: &pb.TalkEnd{BurstId: id}}})
	if st := noaSocket.talkState(t); st.Event != pb.TalkState_ENDED {
		t.Fatalf("a member's ENDED: %v", st)
	}
	env.groupOp(t, hen, "removeFromGroup", g.ID, "noa")
	if s := noaSocket.talk(t, burstID(), "", g.ID); s.Event != pb.TalkState_REFUSED || s.Refusal != pb.SendResult_NOT_MEMBER {
		t.Fatalf("talk after being taken out: %v", s)
	}
}

// A burst wakes a member device without /ws by a talk push, and one with /ws that doesn't acknowledge in time.
func TestTalkWakesPhones(t *testing.T) {
	env, fcm := newPushEnv(t)
	henPhone, henTablet, danaPhone, henSocket, tabletSocket, danaSocket := pushedPair(t, env)
	env.registerPush(t, danaPhone, "dana-token", true)
	env.registerPush(t, henTablet, "tablet-token", true)
	env.closeSocket(t, danaSocket, danaPhone)
	_ = henPhone

	id := burstID()
	if s := henSocket.talk(t, id, "dana", ""); s.Event != pb.TalkState_GRANTED {
		t.Fatalf("talk: %v", s)
	}
	m := fcm.next(t)
	if m.Token != "dana-token" || m.Data["kind"] != "talk" || m.Android.Priority != "HIGH" || m.Android.TTL != "30s" {
		t.Fatalf("the talk push to the sleeping phone: %+v", m)
	}
	// The tablet is connected but stays quiet: it is pushed too after half a second.
	if st := tabletSocket.talkState(t); st.Event != pb.TalkState_STARTED || st.Peer != "dana" {
		t.Fatalf("the talker's own tablet's STARTED: %v", st)
	}
	if m := fcm.next(t); m.Token != "tablet-token" || m.Data["kind"] != "talk" {
		t.Fatalf("the push to a device that didn't acknowledge: %+v", m)
	}
}

// A voice message or an attachment goes up with PUT, resumably, and only the conversation reads it.
func TestBlobUpload(t *testing.T) {
	env := newTestEnv(t)
	env.addUsers(t, "hen", "dana", "eli")
	hen, dana, eli := env.phone(t, "hen"), env.phone(t, "dana"), env.phone(t, "eli")
	env.uploadKeys(t, hen, ecKey())
	env.uploadKeys(t, dana, ecKey())
	henSocket := env.socket(t, hen)
	env.pair(t, dana, []store.Device{dev(dana)}, hen, henSocket)

	id := burstID()
	body := bytes.Repeat([]byte("ciphertext"), 1000)
	if resp, _ := env.blobRequest(t, eli, http.MethodPut, id+"?peer=hen", map[string]string{relay.HeaderTotal: "10000"}, body[:10]); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("an upload for someone not a contact: %d", resp.StatusCode)
	}
	resp, _ := env.blobRequest(t, hen, http.MethodPut, id+"?peer=dana", map[string]string{relay.HeaderTotal: "10000"}, body[:4000])
	if resp.StatusCode != 200 || resp.Header.Get(relay.HeaderOffset) != "4000" || resp.Header.Get(relay.HeaderComplete) != "false" {
		t.Fatalf("the first part: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := env.blobRequest(t, dana, http.MethodGet, id, nil, nil); resp.StatusCode != http.StatusConflict {
		t.Fatalf("GET before the upload is complete: %d", resp.StatusCode)
	}
	if resp, _ := env.blobRequest(t, hen, http.MethodPut, id, map[string]string{relay.HeaderOffset: "3000"}, body[3000:]); resp.StatusCode != http.StatusConflict || resp.Header.Get(relay.HeaderOffset) != "4000" {
		t.Fatalf("a part from the wrong offset: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, _ := env.blobRequest(t, hen, http.MethodHead, id, nil, nil); resp.Header.Get(relay.HeaderOffset) != "4000" {
		t.Fatalf("HEAD: %v", resp.Header)
	}
	if resp, _ := env.blobRequest(t, hen, http.MethodPut, id, map[string]string{relay.HeaderOffset: "4000"}, body[4000:]); resp.StatusCode != 200 || resp.Header.Get(relay.HeaderComplete) != "true" {
		t.Fatalf("the rest: %d %v", resp.StatusCode, resp.Header)
	}
	if resp, data := env.blobRequest(t, dana, http.MethodGet, id, nil, nil); resp.StatusCode != 200 || !bytes.Equal(data, body) {
		t.Fatalf("GET by the peer: %d %d bytes", resp.StatusCode, len(data))
	}
	if resp, _ := env.blobRequest(t, eli, http.MethodGet, id, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET by someone else: %d", resp.StatusCode)
	}
	if resp, _ := env.blobRequest(t, dana, http.MethodPut, id, map[string]string{relay.HeaderOffset: "0"}, body); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("PUT over someone else's blob: %d", resp.StatusCode)
	}
}
