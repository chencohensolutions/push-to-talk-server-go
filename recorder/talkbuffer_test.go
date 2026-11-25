package recorder

import (
	"testing"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
)

func vp8Push(n int) []*rtp.Packet {
	pk := rtp.NewPacketizer(400, 96, 0x1234, &codecs.VP8Payloader{}, rtp.NewFixedSequencer(1), 90000)
	var list []*rtp.Packet
	ts := uint32(1000)
	for i := range n + 1 {
		for _, p := range pk.Packetize(frame(i == 0, i, 600), 3000) {
			p.Timestamp = ts
			list = append(list, p)
		}
		ts += 3000
	}
	return list
}

// A push while the other user isn't in the room is kept for them, they are told, and it goes once they read it all.
func TestTalkBufferKeepsAPushForWhoIsAway(t *testing.T) {
	store, err := blobs.Open(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	told := make(chan Buffered, 1)
	tb := &TalkBuffers{Blobs: store, Tell: func(b Buffered) { told <- b }}
	tr := &talkRoom{room: "talk-x", conv: Conversation{Owner: "hen", Peer: "dana"},
		members: func() []string { return []string{"hen", "dana"} }, present: map[string]bool{"hen.1": true}, stop: make(chan struct{})}
	tb.follow(tr, &packets{vp8Push(5)}, "video/VP8", 90000, "hen.1")
	var b Buffered
	select {
	case b = <-told:
	case <-time.After(2 * time.Second):
		t.Fatal("dana wasn't told")
	}
	if len(b.Readers) != 1 || b.Readers[0] != "dana" || b.Talker != "hen.1" || b.Media != "video" || b.Conv.Peer != "dana" {
		t.Fatalf("buffered: %+v", b)
	}
	m, ok := store.Get(b.Blob)
	if !ok || m.Kind != blobs.TalkBuffer || !m.Complete {
		t.Fatalf("the buffer: %+v %v", m, ok)
	}
	if got := readRecords(t, store, b.Blob); len(got) != 5 || !got[0].key || got[1].at != 33333*time.Microsecond {
		t.Fatalf("records: %d, first key %v", len(got), len(got) > 0 && got[0].key)
	}
	if store.ReadToEnd(b.Blob, "eli") {
		t.Fatal("deleted for someone it isn't for")
	}
	if !store.ReadToEnd(b.Blob, "dana") {
		t.Fatal("not deleted once dana read it")
	}
}

// Everyone in the room: nothing is written.
func TestTalkBufferKeepsNothingWhenNobodyIsAway(t *testing.T) {
	store, err := blobs.Open(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	tb := &TalkBuffers{Blobs: store, Tell: func(b Buffered) { t.Errorf("told: %+v", b) }}
	tr := &talkRoom{room: "talk-x", conv: Conversation{Owner: "hen", Peer: "dana"},
		members: func() []string { return []string{"hen", "dana"} }, present: map[string]bool{"hen.1": true, "dana.2": true}, stop: make(chan struct{})}
	tb.follow(tr, &packets{vp8Push(5)}, "video/VP8", 90000, "hen.1")
	time.Sleep(100 * time.Millisecond)
}
