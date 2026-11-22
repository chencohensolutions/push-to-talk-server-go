package relay

import (
	"context"
	"log"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/chencohensolutions/push-to-talk-server-go/groups"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/push"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
	"google.golang.org/protobuf/proto"
)

// Talk (phase 5a): the server referees each conversation's floor, keeps each burst's clip and forwards its segments
// to the conversation's connected devices; FCM wakes the others. See docs/messaging.md, "Talk".

const (
	// MaxBurst is the longest a talker holds the floor.
	MaxBurst = 60 * time.Second
	// dropGrace is how long the floor waits for a talker whose connection dropped.
	dropGrace = 3 * time.Second
	// ackWait is how long a connected device has to acknowledge a STARTED before it is woken by FCM too.
	ackWait = 500 * time.Millisecond
	// lastSegmentWait is how long a clip waits for its last segment after its talker let go.
	lastSegmentWait = 10 * time.Second
	// MaxSegmentBytes is the most ciphertext one ClipSegment carries (200 ms of 24 kbit/s Opus is about 600 bytes).
	MaxSegmentBytes = 16 << 10
)

// listener is a device a burst goes to, and the conversation as it sees it.
type listener struct {
	device store.Device
	peer   string // the other user of a one-to-one conversation, from this device's side; "" in a group
}

// burst is one talk burst: the floor while it lasts, then its clip until the last segment.
type burst struct {
	id        string
	key       string // the conversation's floor
	talker    store.Device
	peer      string
	group     string
	listeners []listener
	started   time.Time
	next      uint32 // the index the next segment must have
	ended     bool   // the floor is let go
	acked     map[store.Device]bool
	timers    []*time.Timer
}

func floorKey(talker, peer, group string) string {
	if group != "" {
		return "g:" + group
	}
	users := []string{talker, peer}
	if users[0] > users[1] {
		users[0], users[1] = users[1], users[0]
	}
	return "u:" + users[0] + "|" + users[1]
}

// conversation is the devices a burst or a talk from device from to peer or group goes to, or why it may not.
func (r *Relay) conversation(from store.Device, peer, group string) ([]listener, pb.SendResult_Status, string) {
	var out []listener
	if group != "" {
		var ok bool
		var g groups.Group
		if r.Groups != nil {
			g, ok = r.Groups.Get(group)
		}
		if !ok || !g.Member(from.User) {
			return nil, pb.SendResult_NOT_MEMBER, "not in this group"
		}
		targets, err := r.groupTargets(from, g)
		if err != nil {
			return nil, pb.SendResult_STATUS_UNSPECIFIED, "server error"
		}
		for user, active := range targets {
			for n := range active {
				out = append(out, listener{device: store.Device{User: user, Number: n}})
			}
		}
		return out, 0, ""
	}
	switch {
	case peer == from.User:
		return nil, pb.SendResult_INVALID, "a conversation is with another user"
	case r.Users.Find(peer) == nil:
		return nil, pb.SendResult_UNKNOWN_USER, "no such user"
	case r.Book.Blocked(from.User, peer):
		return nil, pb.SendResult_BLOCKED, "blocked"
	case !r.Book.Paired(from.User, peer) && !r.ShareGroup(from.User, peer):
		return nil, pb.SendResult_NOT_PAIRED, "not a contact"
	}
	for _, user := range []string{peer, from.User} {
		active, err := r.ActiveDevices(user)
		if err != nil {
			return nil, pb.SendResult_STATUS_UNSPECIFIED, "server error"
		}
		view := from.User
		if user == from.User {
			delete(active, from.Number)
			view = peer
		}
		for n := range active {
			out = append(out, listener{device: store.Device{User: user, Number: n}, peer: view})
		}
	}
	return out, 0, ""
}

// live queues frame for d's connection, if it has one, behind the frames queued before it. A connection whose
// live queue is full misses it (the clip is still there over /blob).
func (r *Relay) live(d store.Device, frame *pb.Frame) bool {
	r.mu.Lock()
	c := r.conns[d]
	r.mu.Unlock()
	if c == nil {
		return false
	}
	data, err := proto.Marshal(frame)
	if err != nil {
		return false
	}
	select {
	case c.live <- data:
		return true
	default:
		return false
	}
}

func talkFrame(s *pb.TalkState) *pb.Frame { return &pb.Frame{Kind: &pb.Frame_TalkState{TalkState: s}} }

// talkStart answers a TalkStart from c's device.
func (r *Relay) talkStart(ctx context.Context, c *conn, start *pb.TalkStart) error {
	from := c.device
	answer := &pb.TalkState{BurstId: start.GetBurstId(), Peer: start.GetPeer(), Group: start.GetGroup()}
	refuse := func(status pb.SendResult_Status, detail string) error {
		answer.Event, answer.Refusal, answer.Detail = pb.TalkState_REFUSED, status, detail
		log.Printf("Talk from %s.%d refused: %s: %s", from.User, from.Number, status, detail)
		return c.send(ctx, talkFrame(answer))
	}
	if !blobs.ValidID(start.GetBurstId()) {
		return refuse(pb.SendResult_INVALID, "a burst id is 32 lowercase hex digits")
	}
	if (start.GetPeer() == "") == (start.GetGroup() == "") {
		return refuse(pb.SendResult_INVALID, "a TalkStart names a peer or a group")
	}
	listeners, status, detail := r.conversation(from, start.GetPeer(), start.GetGroup())
	if status != 0 {
		return refuse(status, detail)
	}
	key := floorKey(from.User, start.GetPeer(), start.GetGroup())

	r.talkMu.Lock()
	if b := r.bursts[start.GetBurstId()]; b != nil {
		r.talkMu.Unlock()
		if b.talker == from && !b.ended {
			answer.Event, answer.StartedAt = pb.TalkState_GRANTED, b.started.UnixMilli()
			return c.send(ctx, talkFrame(answer))
		}
		return refuse(pb.SendResult_INVALID, "this burst id was used")
	}
	if holder := r.floors[key]; holder != nil {
		r.talkMu.Unlock()
		answer.Event, answer.TalkerUser, answer.TalkerDevice = pb.TalkState_BUSY, holder.talker.User, uint32(holder.talker.Number)
		answer.StartedAt = holder.started.UnixMilli()
		return c.send(ctx, talkFrame(answer))
	}
	if err := r.Blobs.Create(blobs.Meta{ID: start.GetBurstId(), Kind: blobs.Clip, Owner: from.User,
		Peer: start.GetPeer(), Group: start.GetGroup()}); err != nil {
		r.talkMu.Unlock()
		log.Printf("Talk from %s.%d: making its clip: %v", from.User, from.Number, err)
		return refuse(pb.SendResult_INVALID, "this burst id was used")
	}
	b := &burst{id: start.GetBurstId(), key: key, talker: from, peer: start.GetPeer(), group: start.GetGroup(),
		listeners: listeners, started: r.Now(), acked: map[store.Device]bool{}}
	r.floors[key] = b
	r.bursts[b.id] = b
	b.timers = append(b.timers, time.AfterFunc(MaxBurst, func() { r.endFloor(b, pb.TalkState_TIMEOUT) }))
	r.talkMu.Unlock()
	log.Printf("Talk: %s.%d has the floor of %s (burst %s)", from.User, from.Number, key, b.id)

	answer.Event, answer.StartedAt = pb.TalkState_GRANTED, b.started.UnixMilli()
	if err := c.send(ctx, talkFrame(answer)); err != nil {
		return err
	}
	for _, l := range listeners {
		started := &pb.TalkState{Event: pb.TalkState_STARTED, BurstId: b.id, TalkerUser: from.User,
			TalkerDevice: uint32(from.Number), Peer: l.peer, Group: b.group, StartedAt: b.started.UnixMilli()}
		if !r.live(l.device, talkFrame(started)) {
			r.Push.Queued(l.device, push.Talk)
			continue
		}
		d := l.device
		r.talkMu.Lock()
		b.timers = append(b.timers, time.AfterFunc(ackWait, func() {
			r.talkMu.Lock()
			acked := b.acked[d]
			r.talkMu.Unlock()
			if !acked {
				r.Push.Urgent(d, push.Talk)
			}
		}))
		r.talkMu.Unlock()
	}
	return nil
}

// talkAck notes that c's device will play burst id.
func (r *Relay) talkAck(c *conn, ack *pb.TalkAck) {
	r.talkMu.Lock()
	defer r.talkMu.Unlock()
	if b := r.bursts[ack.GetBurstId()]; b != nil {
		b.acked[c.device] = true
	}
}

// clipSegment stores and forwards a segment from c's device, which must be the burst's talker.
func (r *Relay) clipSegment(ctx context.Context, c *conn, seg *pb.ClipSegment) error {
	refuse := func(detail string) error {
		log.Printf("Clip segment from %s.%d refused: %s", c.device.User, c.device.Number, detail)
		return c.send(ctx, talkFrame(&pb.TalkState{Event: pb.TalkState_REFUSED, BurstId: seg.GetBurstId(),
			Refusal: pb.SendResult_INVALID, Detail: detail}))
	}
	r.talkMu.Lock()
	b := r.bursts[seg.GetBurstId()]
	switch {
	case b == nil || b.talker != c.device:
		r.talkMu.Unlock()
		return refuse("no burst of this device has this id")
	case seg.GetIndex() != b.next:
		r.talkMu.Unlock()
		return refuse("segments go in order, with no gaps")
	case len(seg.GetCiphertext()) == 0 || len(seg.GetCiphertext()) > MaxSegmentBytes:
		r.talkMu.Unlock()
		return refuse("a segment holds 1 byte to 16 KB")
	}
	record, _ := proto.Marshal(&pb.ClipSegment{Index: seg.GetIndex(), Last: seg.GetLast(), Ciphertext: seg.GetCiphertext()})
	if err := r.Blobs.AppendRecord(b.id, record, seg.GetLast()); err != nil {
		r.talkMu.Unlock()
		return refuse("the clip can't take it: " + err.Error())
	}
	b.next++
	listeners := b.listeners
	r.talkMu.Unlock()
	frame := &pb.Frame{Kind: &pb.Frame_ClipSegment{ClipSegment: seg}}
	for _, l := range listeners {
		r.live(l.device, frame)
	}
	if seg.GetLast() {
		r.endFloor(b, pb.TalkState_RELEASED)
		r.forgetBurst(b)
	}
	return nil
}

// talkEnd is c's device letting go of burst id.
func (r *Relay) talkEnd(c *conn, end *pb.TalkEnd) {
	r.talkMu.Lock()
	b := r.bursts[end.GetBurstId()]
	r.talkMu.Unlock()
	if b != nil && b.talker == c.device {
		r.endFloor(b, pb.TalkState_RELEASED)
	}
}

// endFloor lets b's floor go, once, and tells every device of the conversation. A burst that timed out or dropped
// has its clip completed now; one let go waits a moment for its last segment.
func (r *Relay) endFloor(b *burst, reason pb.TalkState_EndReason) {
	r.talkMu.Lock()
	if b.ended {
		r.talkMu.Unlock()
		return
	}
	b.ended = true
	if r.floors[b.key] == b {
		delete(r.floors, b.key)
	}
	r.talkMu.Unlock()
	log.Printf("Talk: %s.%d let go of %s (%s)", b.talker.User, b.talker.Number, b.key, reason)
	for _, l := range b.listeners {
		r.live(l.device, talkFrame(&pb.TalkState{Event: pb.TalkState_ENDED, BurstId: b.id, TalkerUser: b.talker.User,
			TalkerDevice: uint32(b.talker.Number), Peer: l.peer, Group: b.group, EndReason: reason,
			StartedAt: b.started.UnixMilli()}))
	}
	r.live(b.talker, talkFrame(&pb.TalkState{Event: pb.TalkState_ENDED, BurstId: b.id, TalkerUser: b.talker.User,
		TalkerDevice: uint32(b.talker.Number), Peer: b.peer, Group: b.group, EndReason: reason,
		StartedAt: b.started.UnixMilli()}))
	if reason != pb.TalkState_RELEASED {
		r.forgetBurst(b)
		return
	}
	r.talkMu.Lock()
	b.timers = append(b.timers, time.AfterFunc(lastSegmentWait, func() { r.forgetBurst(b) }))
	r.talkMu.Unlock()
}

// forgetBurst completes b's clip and drops what is kept of b in memory.
func (r *Relay) forgetBurst(b *burst) {
	if err := r.Blobs.Finish(b.id); err != nil {
		log.Printf("Talk: completing clip %s: %v", b.id, err)
	}
	r.talkMu.Lock()
	defer r.talkMu.Unlock()
	if r.bursts[b.id] == b {
		delete(r.bursts, b.id)
	}
	if b.ended {
		for _, t := range b.timers {
			t.Stop()
		}
	}
}

// talkerGone is d's connection closing: a floor it holds goes after dropGrace unless it connected again.
func (r *Relay) talkerGone(d store.Device) {
	r.talkMu.Lock()
	defer r.talkMu.Unlock()
	for _, b := range r.floors {
		if b.talker == d {
			b := b
			b.timers = append(b.timers, time.AfterFunc(dropGrace, func() {
				if !r.Connected(d) {
					r.endFloor(b, pb.TalkState_DROPPED)
				}
			}))
		}
	}
}
