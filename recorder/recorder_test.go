package recorder

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"testing"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
)

// packets is a track that plays back RTP packets, then ends.
type packets struct{ list []*rtp.Packet }

func (p *packets) ReadRTP() (*rtp.Packet, interceptor.Attributes, error) {
	if len(p.list) == 0 {
		return nil, nil, io.EOF
	}
	next := p.list[0]
	p.list = p.list[1:]
	return next, nil, nil
}

// frame is a stand-in for an encrypted VP8 frame: the clear frame tag (key frame or not), then bytes that look random.
func frame(key bool, n int, size int) []byte {
	f := make([]byte, size)
	for i := range f {
		f[i] = byte(i*7 + n)
	}
	if key {
		f[0] &^= 1
	} else {
		f[0] |= 1
	}
	return f
}

type record struct {
	at    time.Duration
	key   bool
	frame []byte
}

func readRecords(t *testing.T, store *blobs.Store, id string) []record {
	t.Helper()
	f, err := store.OpenData(id)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, _ := io.ReadAll(f)
	var out []record
	for len(data) > 0 {
		n := binary.BigEndian.Uint32(data)
		body := data[4 : 4+n]
		data = data[4+n:]
		out = append(out, record{at: time.Duration(binary.BigEndian.Uint64(body)) * time.Microsecond,
			key: body[8]&1 == 1, frame: append([]byte{}, body[9:]...)})
	}
	return out
}

func TestWriteKeepsFramesAsTheyCame(t *testing.T) {
	store, err := blobs.Open(t.TempDir(), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	clock := started.Add(1500 * time.Millisecond) // the track's first frame came 1.5 s into the recording
	r := &Recorder{Blobs: store, Now: func() time.Time { return clock }}

	// Ten VP8 frames, 33 ms apart (3000 ticks of 90 kHz), the first and sixth key frames, split into RTP packets of at
	// most 400 bytes; the RTP timestamp wraps on the way. Two packets come out of order.
	pk := rtp.NewPacketizer(400, 96, 0x1234, &codecs.VP8Payloader{}, rtp.NewFixedSequencer(65530), 90000)
	var frames [][]byte
	var list []*rtp.Packet
	ts := uint32(0xFFFFFFFF - 5000)
	for i := range 10 {
		f := frame(i == 0 || i == 5, i, 1000+i*37)
		frames = append(frames, f)
		for _, p := range pk.Packetize(f, 3000) {
			p.Timestamp = ts
			list = append(list, p)
		}
		ts += 3000
	}
	list[3], list[4] = list[4], list[3]
	// One more frame, so the builder lets the tenth one out.
	for _, p := range pk.Packetize(frame(false, 10, 50), 3000) {
		p.Timestamp = ts
		list = append(list, p)
	}

	conv := Conversation{Owner: "hen", Peer: "dana"}
	id, err := r.Write("c1", conv, started, &packets{list}, "video/VP8", 90000, "hen.1")
	if err != nil {
		t.Fatal(err)
	}
	m, _ := store.Get(id)
	if m.Kind != blobs.Track || !m.Complete || m.Owner != "hen" || m.Peer != "dana" || m.Track.Call != "c1" ||
		m.Track.Identity != "hen.1" || m.Track.Media != "video" || m.Track.Codec != "video/VP8" ||
		!m.Track.Recording.Equal(started.UTC()) {
		t.Fatalf("the track's meta: %+v %+v", m, m.Track)
	}
	got := readRecords(t, store, id)
	if len(got) < 10 {
		t.Fatalf("%d records, want at least 10", len(got))
	}
	for i := range 10 {
		want := 1500*time.Millisecond + time.Duration(i)*3000*time.Second/90000
		if !bytes.Equal(got[i].frame, frames[i]) || got[i].key != (i == 0 || i == 5) ||
			(got[i].at-want).Abs() > time.Millisecond {
			t.Fatalf("record %d: at %v (want %v), key %v, %d bytes (want %d)", i, got[i].at, want, got[i].key,
				len(got[i].frame), len(frames[i]))
		}
	}
	if calls := store.OfCall("c1"); len(calls) != 1 || calls[0].ID != id {
		t.Fatalf("the call's tracks: %v", calls)
	}
	// Kept calls aren't deleted with the other blobs.
	if store.Expire(time.Now().Add(time.Hour)) != 0 {
		t.Fatal("a kept call's track expired")
	}
	if _, err := os.Stat(store.Root() + "/" + id + ".blob"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteOpus(t *testing.T) {
	store, _ := blobs.Open(t.TempDir(), time.Now)
	started := time.Now()
	r := &Recorder{Blobs: store, Now: func() time.Time { return started }}
	pk := rtp.NewPacketizer(1200, 111, 1, &codecs.OpusPayloader{}, rtp.NewRandomSequencer(), 48000)
	var list []*rtp.Packet
	for i := range 6 {
		list = append(list, pk.Packetize([]byte{byte(i), 1, 2, 3}, 960)...)
	}
	id, err := r.Write("c2", Conversation{Owner: "hen", Group: "g1"}, started, &packets{list}, "audio/opus", 48000, "hen.1")
	if err != nil {
		t.Fatal(err)
	}
	got := readRecords(t, store, id)
	if len(got) < 5 {
		t.Fatalf("%d records", len(got))
	}
	for i, rec := range got[:5] {
		if !rec.key || rec.frame[0] != byte(i) || rec.at != time.Duration(i)*20*time.Millisecond {
			t.Fatalf("record %d: %+v", i, rec)
		}
	}
	if m, _ := store.Get(id); m.Track.Media != "audio" || m.Group != "g1" {
		t.Fatalf("meta: %+v", m)
	}
	if _, err := r.Write("c2", Conversation{Owner: "hen"}, started, &packets{}, "video/AV1", 90000, "hen.1"); err == nil {
		t.Fatal("an AV1 track was taken")
	}
}

// The phones send call audio as RED (2026-11-22: LiveKit doesn't strip it from an encrypted track, so calls were kept
// without sound). Its headers are inside the encryption, so the recorder keeps each payload whole, as audio/red.
func TestWriteKeepsREDPayloadsWhole(t *testing.T) {
	store, _ := blobs.Open(t.TempDir(), time.Now)
	started := time.Now()
	r := &Recorder{Blobs: store, Now: func() time.Time { return started }}
	var list []*rtp.Packet
	for i := range 6 {
		list = append(list, &rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 63, SequenceNumber: uint16(100 + i),
			Timestamp: uint32(5000 + 960*i), Marker: true}, Payload: []byte{byte(i), 0xAA, 0xBB, 0xCC}})
	}
	id, err := r.Write("c3", Conversation{Owner: "hen", Peer: "dana"}, started, &packets{list}, "audio/red", 48000, "hen.1")
	if err != nil {
		t.Fatal(err)
	}
	got := readRecords(t, store, id)
	if len(got) < 5 {
		t.Fatalf("%d records", len(got))
	}
	for i, rec := range got[:5] {
		if !bytes.Equal(rec.frame, []byte{byte(i), 0xAA, 0xBB, 0xCC}) || rec.at != time.Duration(i)*20*time.Millisecond {
			t.Fatalf("record %d: %+v", i, rec)
		}
	}
	if m, _ := store.Get(id); m.Track.Media != "audio" || m.Track.Codec != "audio/red" {
		t.Fatalf("meta: %+v", m.Track)
	}
}

func TestWriteH265(t *testing.T) {
	store, _ := blobs.Open(t.TempDir(), time.Now)
	started := time.Now()
	r := &Recorder{Blobs: store, Now: func() time.Time { return started }}
	// Frames as LiveKit's H.265 encryption leaves them: Annex B NAL units whose two-byte headers are clear. The first
	// is a key frame (VPS, then an IDR slice, type 19), the others trailing slices (type 1).
	nal := func(typ byte, n int) []byte {
		b := []byte{0, 0, 0, 1, typ << 1, 1}
		for i := range n {
			b = append(b, byte(i*13+int(typ)))
		}
		return b
	}
	frames := [][]byte{append(nal(32, 20), nal(19, 3000)...), nal(1, 900), nal(1, 1200), nal(1, 40)}
	pk := rtp.NewPacketizer(1200, 116, 0x99, &codecs.H265Payloader{}, rtp.NewFixedSequencer(10), 90000)
	var list []*rtp.Packet
	for i, f := range frames {
		for _, p := range pk.Packetize(f, 3000) {
			p.Timestamp = uint32(1000 + 3000*i)
			list = append(list, p)
		}
	}
	id, err := r.Write("c4", Conversation{Owner: "hen", Peer: "dana"}, started, &packets{list}, "video/H265", 90000, "hen.1")
	if err != nil {
		t.Fatal(err)
	}
	got := readRecords(t, store, id)
	if len(got) < 3 {
		t.Fatalf("%d records", len(got))
	}
	for i, rec := range got[:3] {
		if rec.key != (i == 0) || !bytes.Contains(rec.frame, frames[i][4:]) {
			t.Fatalf("record %d: key %v, %d bytes", i, rec.key, len(rec.frame))
		}
	}
	if m, _ := store.Get(id); m.Track.Media != "video" || m.Track.Codec != "video/H265" {
		t.Fatalf("meta: %+v", m.Track)
	}
}
