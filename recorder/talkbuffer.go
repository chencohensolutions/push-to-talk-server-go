package recorder

import (
	"encoding/binary"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/chencohensolutions/push-to-talk-server-go/livekit"
	lkproto "github.com/livekit/protocol/livekit"
	lksdk "github.com/livekit/server-sdk-go/v2"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media/samplebuilder"
)

// Talk buffer (docs/messaging.md, "Talk buffer"; 2026-11-25, hen: "server buffer", each push sent once). The recorder
// joins a chat's talk room as soon as a phone asks for its token, hidden and sending nothing, and takes every talker's
// microphone and camera. A push is a talker's track from its first packet after a pause to the next pause (a muted
// track sends nothing). While any member of the chat isn't in the room, the push's frames (still encrypted end to end
// with the talker's room key) go into a TalkBuffer blob for the members who are missing, and they are told
// (Buffered). When nobody is missing, nothing is written.

// PushGap is how long a track sends nothing before its push is over.
const PushGap = 700 * time.Millisecond

// Buffered is a push kept for Readers: its blob, its room, its conversation and talker (user.device), media
// ("audio" or "video"), codec and when it began.
type Buffered struct {
	Blob, Room string
	Conv       Conversation
	Talker     string
	Media      string
	Codec      string
	Started    time.Time
	Readers    []string
}

// TalkBuffers keeps the pushes of the talk rooms it is in.
type TalkBuffers struct {
	Keys  livekit.Keys
	URL   string
	Blobs *blobs.Store
	Now   func() time.Time
	// Join connects to a room (lksdk.ConnectToRoomWithToken when nil); tests replace it.
	Join func(url, token string, cb *lksdk.RoomCallback) (Room, error)
	// Tell is told of each push kept (on its own goroutine): the relay tells the readers' devices.
	Tell func(b Buffered)

	mu    sync.Mutex
	rooms map[string]*talkRoom
}

type talkRoom struct {
	room    string
	conv    Conversation
	members func() []string
	lkRoom  Room
	present map[string]bool // identities (user.device) in the room, the recorder aside
	stop    chan struct{}
}

func (t *TalkBuffers) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// Watch puts the recorder in room (conv's talk room; members answers the chat's users now), if it isn't there yet.
// It returns at once; joining goes on in the background.
func (t *TalkBuffers) Watch(room string, conv Conversation, members func() []string) {
	t.mu.Lock()
	if t.rooms == nil {
		t.rooms = map[string]*talkRoom{}
	}
	if _, ok := t.rooms[room]; ok {
		t.mu.Unlock()
		return
	}
	tr := &talkRoom{room: room, conv: conv, members: members, present: map[string]bool{}, stop: make(chan struct{})}
	t.rooms[room] = tr
	t.mu.Unlock()
	token, err := t.Keys.RecorderToken(room, t.now())
	if err != nil {
		log.Printf("Talk buffer: a token for %s: %v", room, err)
		t.forget(tr)
		return
	}
	go t.join(tr, token)
}

func (t *TalkBuffers) forget(tr *talkRoom) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rooms[tr.room] == tr {
		delete(t.rooms, tr.room)
		close(tr.stop)
	}
}

func (t *TalkBuffers) join(tr *talkRoom, token string) {
	cb := &lksdk.RoomCallback{
		ParticipantCallback: lksdk.ParticipantCallback{
			OnTrackSubscribed: func(track *webrtc.TrackRemote, pub *lksdk.RemoteTrackPublication, rp *lksdk.RemoteParticipant) {
				if track.Kind() == webrtc.RTPCodecTypeVideo {
					pub.SetVideoQuality(lkproto.VideoQuality_HIGH)
				}
				go t.follow(tr, track, track.Codec().MimeType, track.Codec().ClockRate, rp.Identity())
			},
		},
		OnParticipantConnected: func(rp *lksdk.RemoteParticipant) {
			t.mu.Lock()
			tr.present[rp.Identity()] = true
			t.mu.Unlock()
		},
		OnParticipantDisconnected: func(rp *lksdk.RemoteParticipant) {
			t.mu.Lock()
			delete(tr.present, rp.Identity())
			t.mu.Unlock()
			t.leaveIfEmpty(tr)
		},
		OnDisconnected: func() { t.forget(tr) },
	}
	join := t.Join
	if join == nil {
		join = func(url, token string, cb *lksdk.RoomCallback) (Room, error) {
			lr, err := lksdk.ConnectToRoomWithToken(url, token, cb, lksdk.WithAutoSubscribe(true),
				lksdk.WithCodecs(codecsToTake))
			if err != nil {
				return nil, err
			}
			for _, rp := range lr.GetRemoteParticipants() {
				t.mu.Lock()
				tr.present[rp.Identity()] = true
				t.mu.Unlock()
			}
			return sdkRoom{lr}, nil
		}
	}
	lr, err := join(t.URL, token, cb)
	if err != nil {
		log.Printf("Talk buffer: joining %s: %v", tr.room, err)
		t.forget(tr)
		return
	}
	t.mu.Lock()
	tr.lkRoom = lr
	t.mu.Unlock()
	log.Printf("Talk buffer: in %s", tr.room)
	// A room nobody is in any more is left (the next token puts the recorder back).
	go func() {
		tick := time.NewTicker(NobodyCame)
		defer tick.Stop()
		for {
			select {
			case <-tr.stop:
				return
			case <-tick.C:
				t.leaveIfEmpty(tr)
			}
		}
	}()
}

func (t *TalkBuffers) leaveIfEmpty(tr *talkRoom) {
	t.mu.Lock()
	room := tr.lkRoom
	empty := len(tr.present) == 0
	t.mu.Unlock()
	if room != nil && empty && room.RemoteParticipantCount() == 0 {
		room.Disconnect()
		t.forget(tr)
		log.Printf("Talk buffer: left %s (nobody in it)", tr.room)
	}
}

// Missing answers the members of tr's chat who aren't in the room now, the talker's user aside.
func (t *TalkBuffers) missing(tr *talkRoom, talkerUser string) []string {
	t.mu.Lock()
	in := map[string]bool{}
	for identity := range tr.present {
		in[identityUser(identity)] = true
	}
	t.mu.Unlock()
	var out []string
	for _, m := range tr.members() {
		if m != talkerUser && !in[m] && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// identityUser is the user of a LiveKit identity "user.device".
func identityUser(identity string) string {
	if i := strings.LastIndexByte(identity, '.'); i > 0 {
		return identity[:i]
	}
	return identity
}

// push is one push being kept.
type push struct {
	blob    string // "" when nobody was missing: nothing kept
	started time.Time
	last    uint32
	ticks   int64
	have    bool
}

// follow keeps the pushes of one talker's track until it ends.
func (t *TalkBuffers) follow(tr *talkRoom, track RTPReader, mime string, clockRate uint32, identity string) {
	depack, keyFrame, err := depacketizer(mime)
	if err != nil || clockRate == 0 {
		log.Printf("Talk buffer: %s's %s in %s: not kept (%v)", identity, mime, tr.room, err)
		return
	}
	media := "video"
	if strings.HasPrefix(strings.ToLower(mime), "audio/") {
		media = "audio"
	}
	talker := identityUser(identity)
	var mu sync.Mutex
	var cur *push
	lastPacket := t.now()
	end := func() {
		if cur != nil && cur.blob != "" {
			t.Blobs.Finish(cur.blob)
		}
		cur = nil
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		tick := time.NewTicker(PushGap / 4)
		defer tick.Stop()
		for {
			select {
			case <-done:
				mu.Lock()
				end()
				mu.Unlock()
				return
			case <-tick.C:
				mu.Lock()
				if cur != nil && t.now().Sub(lastPacket) > PushGap {
					end()
				}
				mu.Unlock()
			}
		}
	}()
	builder := samplebuilder.New(512, depack, clockRate)
	for {
		packet, _, err := track.ReadRTP()
		if err != nil {
			mu.Lock()
			end() // the track ended: its push is complete
			mu.Unlock()
			return
		}
		mu.Lock()
		lastPacket = t.now()
		builder.Push(packet)
		for sample := builder.Pop(); sample != nil; sample = builder.Pop() {
			if cur == nil {
				cur = &push{started: t.now()}
				if readers := t.missing(tr, talker); len(readers) > 0 {
					cur.blob = t.start(tr, identity, media, mime, cur.started, readers)
				}
			}
			if cur.blob == "" {
				continue
			}
			if !cur.have {
				cur.last, cur.have = sample.PacketTimestamp, true
			}
			cur.ticks += int64(int32(sample.PacketTimestamp - cur.last))
			cur.last = sample.PacketTimestamp
			record := binary.BigEndian.AppendUint64(nil, uint64(max(cur.ticks*1_000_000/int64(clockRate), 0)))
			var flags byte
			if keyFrame(sample.Data) {
				flags |= 1
			}
			record = append(append(record, flags), sample.Data...)
			if err := t.Blobs.AppendRecord(cur.blob, record, false); err != nil {
				log.Printf("Talk buffer %s: %v", cur.blob, err)
				cur.blob = ""
			}
		}
		mu.Unlock()
	}
}

// start makes the TalkBuffer blob of a push and tells its readers; it answers the blob's id, or "".
func (t *TalkBuffers) start(tr *talkRoom, identity, media, mime string, started time.Time, readers []string) string {
	id := newBlobID()
	talker := identityUser(identity)
	conv := Conversation{Owner: talker, Group: tr.conv.Group}
	if conv.Group == "" {
		// One to one: the other user, from the talker's side.
		for _, m := range tr.members() {
			if m != talker {
				conv.Peer = m
			}
		}
	}
	err := t.Blobs.Create(blobs.Meta{ID: id, Kind: blobs.TalkBuffer, Owner: conv.Owner, Peer: conv.Peer, Group: conv.Group,
		Readers: readers, Track: &blobs.TrackInfo{Call: tr.room, Identity: identity, Media: media, Codec: mime,
			Started: started.UTC(), Recording: started.UTC()}})
	if err != nil {
		log.Printf("Talk buffer: a blob for %s's push in %s: %v", identity, tr.room, err)
		return ""
	}
	log.Printf("Talk buffer: %s's %s push in %s kept in %s for %v", identity, media, tr.room, id, readers)
	if t.Tell != nil {
		go t.Tell(Buffered{Blob: id, Room: tr.room, Conv: conv, Talker: identity, Media: media, Codec: mime,
			Started: started, Readers: readers})
	}
	return id
}

// StopAll leaves every talk room (the server stopping).
func (t *TalkBuffers) StopAll() {
	t.mu.Lock()
	var rooms []*talkRoom
	for _, tr := range t.rooms {
		rooms = append(rooms, tr)
	}
	t.mu.Unlock()
	for _, tr := range rooms {
		if tr.lkRoom != nil {
			tr.lkRoom.Disconnect()
		}
		t.forget(tr)
	}
}
