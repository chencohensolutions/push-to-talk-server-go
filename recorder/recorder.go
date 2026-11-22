// Package recorder keeps calls without re-encoding them, kept forever until a way to delete is decided. 2026-11-22
// 18:09 (hen): only while someone in the call records it. From a participant's recordCall until stopRecordingCall (or
// until the device that started it leaves), ptt-server is in the call's LiveKit room as a hidden participant
// that sends nothing, takes every participant's audio and video (the best video layer), and writes each stream's
// frames, as they arrive, into a Track blob. The frames stay encrypted end to end with the call's key, which the
// server never has. The phones in the call download the tracks and decrypt each frame into one Matroska file, a video
// and an audio track per person, without re-encoding. See docs/messaging.md, "Saved calls".
//
// A track blob is records (package blobs: a 4-byte big-endian length, then the record) of:
//
//	8 bytes  big-endian microseconds since the recording began (the same clock for every track of the call)
//	1 byte   flags: 1 = a key frame (video; every audio frame has it)
//	...      the frame, as the sender's LiveKit encrypted it (codec header bytes clear, then ciphertext, IV, key index)
package recorder

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/chencohensolutions/push-to-talk-server-go/livekit"
	lkproto "github.com/livekit/protocol/livekit"
	lksdk "github.com/livekit/server-sdk-go/v2"
	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/rtp/codecs"
	"github.com/pion/webrtc/v4"
	"github.com/pion/webrtc/v4/pkg/media/samplebuilder"
)

// MaxLength is the longest a call is kept for; the recorder leaves after it. NobodyCame is how long it waits in a
// room nobody joined.
const (
	MaxLength  = 4 * time.Hour
	NobodyCame = 2 * time.Minute
)

// Conversation is whose a saved call is: the user who asked, and the other user of a one-to-one conversation or the
// group. Its tracks may be read by the same people as its other blobs (relay's mayRead).
type Conversation struct {
	Owner, Peer, Group string
}

// Recorder keeps the calls being saved now.
type Recorder struct {
	Keys livekit.Keys
	// LiveKit's signalling on loopback (http://127.0.0.1:7880; the SDK takes ws:// or http://).
	URL   string
	Blobs *blobs.Store
	Now   func() time.Time
	// Join connects to a room (lksdk.ConnectToRoomWithToken when nil); tests replace it.
	Join func(url, token string, cb *lksdk.RoomCallback) (Room, error)
	// Changed, when set, is told each time a call's recording starts (once the recorder is in the room) or stops, so
	// everyone in the call can be shown it (serve.go puts it in the room's metadata). It runs on its own goroutine.
	Changed func(room string, s Status)

	mu    sync.Mutex
	calls map[string]*recording
}

// Room is the part of a LiveKit room the recorder uses.
type Room interface {
	Disconnect()
	RemoteParticipantCount() int
}

type sdkRoom struct{ *lksdk.Room }

func (r sdkRoom) RemoteParticipantCount() int { return len(r.GetRemoteParticipants()) }

type recording struct {
	call    string
	room    string
	by      string // the participant (user.device) who started it: the recording stops when it leaves
	conv    Conversation
	started time.Time
	lkRoom  Room
	stop    chan struct{}
	stopped bool
}

// Status is a call's saving: whether it goes on now, when it began and who started it (user.device).
type Status struct {
	Recording bool
	Started   time.Time
	By        string
}

func (rec *recording) status() Status {
	return Status{Recording: !rec.stopped, Started: rec.started, By: rec.by}
}

func (r *Recorder) changed(rec *recording, s Status) {
	if r.Changed != nil {
		go r.Changed(rec.room, s)
	}
}

func (r *Recorder) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Start begins keeping call (room is its LiveKit room) for conv, started by the participant by (user.device), or
// answers the keeping that goes on already. It returns at once: the join and the recording go on in the background, so a call is never held up or failed by the
// recorder. The error is only for a bad token; a join that fails is logged and the recording is forgotten.
func (r *Recorder) Start(call, room string, conv Conversation, by string) (Status, error) {
	r.mu.Lock()
	if r.calls == nil {
		r.calls = map[string]*recording{}
	}
	if rec, ok := r.calls[call]; ok && !rec.stopped {
		r.mu.Unlock()
		return rec.status(), nil
	}
	rec := &recording{call: call, room: room, by: by, conv: conv, started: r.now(), stop: make(chan struct{})}
	r.calls[call] = rec
	r.mu.Unlock()

	token, err := r.Keys.RecorderToken(room, rec.started)
	if err != nil {
		r.forget(rec)
		return Status{}, err
	}
	go r.join(rec, call, room, token)
	return rec.status(), nil
}

// join connects the recorder to the call's room in the background and sets the timers.
func (r *Recorder) join(rec *recording, call, room, token string) {
	cb := &lksdk.RoomCallback{
		ParticipantCallback: lksdk.ParticipantCallback{
			OnTrackSubscribed: func(track *webrtc.TrackRemote, pub *lksdk.RemoteTrackPublication, rp *lksdk.RemoteParticipant) {
				if track.Kind() == webrtc.RTPCodecTypeVideo {
					pub.SetVideoQuality(lkproto.VideoQuality_HIGH) // the best layer, whatever the screens show
				}
				go r.keep(rec, track, track.Codec().MimeType, track.Codec().ClockRate, rp.Identity())
			},
		},
		OnParticipantDisconnected: func(rp *lksdk.RemoteParticipant) {
			if rp.Identity() == rec.by { // whoever recorded left: the call isn't recorded any more
				r.Stop(call)
				return
			}
			r.leaveIfEmpty(rec)
		},
		OnDisconnected: func() { r.Stop(call) },
	}
	join := r.Join
	if join == nil {
		join = func(url, token string, cb *lksdk.RoomCallback) (Room, error) {
			lr, err := lksdk.ConnectToRoomWithToken(url, token, cb, lksdk.WithAutoSubscribe(true))
			if err != nil {
				return nil, err
			}
			return sdkRoom{lr}, nil
		}
	}
	lr, err := join(r.URL, token, cb)
	if err != nil {
		log.Printf("Recorder: joining call %s: %v", call, err)
		r.forget(rec)
		return
	}
	r.mu.Lock()
	rec.lkRoom = lr
	stopped := rec.stopped
	status := rec.status()
	r.mu.Unlock()
	if stopped { // stopped while joining
		lr.Disconnect()
		return
	}
	r.changed(rec, status)
	go func() {
		select {
		case <-rec.stop:
			return
		case <-time.After(NobodyCame):
			r.leaveIfEmpty(rec) // the call was never answered, or its caller gave up
		}
		select {
		case <-rec.stop:
		case <-time.After(MaxLength - NobodyCame):
			log.Printf("Recorder: call %s reached %s, keeping stops", call, MaxLength)
			r.Stop(call)
		}
	}()
	log.Printf("Recorder: keeping call %s, recorded by %s", call, rec.by)
}

func (r *Recorder) forget(rec *recording) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls[rec.call] == rec {
		delete(r.calls, rec.call)
	}
}

// leaveIfEmpty stops the saving once nobody but the recorder is in the room.
func (r *Recorder) leaveIfEmpty(rec *recording) {
	r.mu.Lock()
	room := rec.lkRoom
	r.mu.Unlock()
	if room != nil && room.RemoteParticipantCount() == 0 {
		r.Stop(rec.call)
	}
}

// Stop ends saving call: the recorder leaves its room, and each of its tracks is completed.
func (r *Recorder) Stop(call string) Status {
	r.mu.Lock()
	rec, ok := r.calls[call]
	if !ok || rec.stopped {
		r.mu.Unlock()
		if ok {
			return rec.status()
		}
		return Status{}
	}
	rec.stopped = true
	close(rec.stop)
	room := rec.lkRoom
	status := rec.status()
	r.mu.Unlock()
	if room != nil {
		room.Disconnect()
		r.changed(rec, status) // told only if it was told it started
	}
	log.Printf("Recorder: call %s saved", call)
	return status
}

// Status is call's saving now.
func (r *Recorder) Status(call string) Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.calls[call]
	if !ok {
		return Status{}
	}
	return rec.status()
}

// StopAll ends every saving (the server stopping).
func (r *Recorder) StopAll() {
	r.mu.Lock()
	var calls []string
	for call := range r.calls {
		calls = append(calls, call)
	}
	r.mu.Unlock()
	for _, call := range calls {
		r.Stop(call)
	}
}

// RTPReader is where a track's packets come from (a webrtc.TrackRemote).
type RTPReader interface {
	ReadRTP() (*rtp.Packet, interceptor.Attributes, error)
}

func newBlobID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// depacketizer is the RTP depacketizer for a codec, and whether a frame of it is a key frame.
func depacketizer(mime string) (rtp.Depacketizer, func(frame []byte) bool, error) {
	switch strings.ToLower(mime) {
	case strings.ToLower(webrtc.MimeTypeOpus):
		return &codecs.OpusPacket{}, func([]byte) bool { return true }, nil
	case strings.ToLower(webrtc.MimeTypeVP8):
		// LiveKit's frame encryption leaves the VP8 frame tag clear: bit 0 of its first byte is 0 on a key frame.
		return &codecs.VP8Packet{}, func(f []byte) bool { return len(f) > 0 && f[0]&1 == 0 }, nil
	case strings.ToLower(webrtc.MimeTypeH264):
		// Annex B NAL units, their one-byte headers clear: an IDR slice (5) or a sequence parameter set (7).
		return &codecs.H264Packet{}, func(f []byte) bool {
			for i := 0; i+3 < len(f); i++ {
				if f[i] == 0 && f[i+1] == 0 && f[i+2] == 1 {
					if t := f[i+3] & 0x1f; t == 5 || t == 7 {
						return true
					}
				}
			}
			return false
		}, nil
	}
	return nil, nil, fmt.Errorf("the recorder keeps Opus, VP8 and H.264, not %s", mime)
}

// keep writes one participant's track to a new Track blob until it ends.
func (r *Recorder) keep(rec *recording, track RTPReader, mime string, clockRate uint32, identity string) {
	id, err := r.Write(rec.call, rec.conv, rec.started, track, mime, clockRate, identity)
	if err != nil {
		log.Printf("Recorder: call %s, %s's %s: %v", rec.call, identity, mime, err)
	} else {
		log.Printf("Recorder: call %s, %s's %s kept in blob %s", rec.call, identity, mime, id)
	}
}

// Write keeps the frames of track (codec mime, its RTP clock rate) from identity, in call (being saved since
// started), in a new Track blob until the track ends, and answers the blob's id.
func (r *Recorder) Write(call string, conv Conversation, started time.Time, track RTPReader, mime string,
	clockRate uint32, identity string) (string, error) {
	depack, keyFrame, err := depacketizer(mime)
	if err != nil {
		return "", err
	}
	if clockRate == 0 {
		return "", errors.New("the track has no clock rate")
	}
	media := "video"
	if strings.HasPrefix(strings.ToLower(mime), "audio/") {
		media = "audio"
	}
	id := newBlobID()
	first := r.now()
	err = r.Blobs.Create(blobs.Meta{ID: id, Kind: blobs.Track, Owner: conv.Owner, Peer: conv.Peer, Group: conv.Group,
		Track: &blobs.TrackInfo{Call: call, Identity: identity, Media: media, Codec: mime, Started: first.UTC(),
			Recording: started.UTC()}})
	if err != nil {
		return "", err
	}
	defer r.Blobs.Finish(id)
	// Up to 512 packets late are put back in order (a second of video at a high bit rate).
	builder := samplebuilder.New(512, depack, clockRate)
	offset := first.Sub(started).Microseconds()
	var last uint32
	var ticks int64 // RTP clock ticks since the first frame, unwrapped
	have := false
	for {
		packet, _, err := track.ReadRTP()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return id, nil
			}
			return id, nil // the track or the room closed: what arrived is kept
		}
		builder.Push(packet)
		for sample := builder.Pop(); sample != nil; sample = builder.Pop() {
			if !have {
				last, have = sample.PacketTimestamp, true
			}
			ticks += int64(int32(sample.PacketTimestamp - last))
			last = sample.PacketTimestamp
			at := offset + ticks*1_000_000/int64(clockRate)
			record := binary.BigEndian.AppendUint64(nil, uint64(max(at, 0)))
			var flags byte
			if keyFrame(sample.Data) {
				flags |= 1
			}
			record = append(record, flags)
			record = append(record, sample.Data...)
			if err := r.Blobs.AppendRecord(id, record, false); err != nil {
				return id, err
			}
		}
	}
}
