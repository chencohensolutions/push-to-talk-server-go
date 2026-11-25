package relay

import (
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/push"
	"github.com/chencohensolutions/push-to-talk-server-go/recorder"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
)

// TellBuffered tells the readers of a push the recorder kept (docs/messaging.md, "Talk buffer"): each of their active
// devices gets a BufferedTalk frame on /ws, or a talk push when it has none. Members who left the group, or block the
// talker, are not told.
func (r *Relay) TellBuffered(b recorder.Buffered) {
	for _, user := range b.Readers {
		if b.Conv.Group != "" {
			g, ok := r.Groups.Get(b.Conv.Group)
			if !ok || !g.Member(user) {
				continue
			}
		}
		if r.Book != nil && r.Book.Blocked(user, b.Conv.Owner) {
			continue
		}
		active, err := r.ActiveDevices(user)
		if err != nil {
			continue
		}
		peer := ""
		if b.Conv.Group == "" {
			peer = b.Conv.Owner // the talker, from the reader's side
		}
		frame := &pb.Frame{Kind: &pb.Frame_BufferedTalk{BufferedTalk: &pb.BufferedTalk{BlobId: b.Blob, Talker: b.Talker,
			Peer: peer, Group: b.Conv.Group, Media: b.Media, Codec: b.Codec, StartedAt: b.Started.UnixMilli(),
			BurstId: r.burstOf(b.Conv.Owner, b.Conv.Peer, b.Conv.Group)}}}
		for n := range active {
			d := store.Device{User: user, Number: n}
			if !r.live(d, frame) && r.Push != nil {
				r.Push.Urgent(d, push.Talk)
			}
		}
	}
}

// burstOf is the burst talker holds now in the conversation with peer or group, or "".
func (r *Relay) burstOf(talker, peer, group string) string {
	key := floorKey(talker, peer, group) + ">" + talker
	r.talkMu.Lock()
	defer r.talkMu.Unlock()
	if b := r.floors[key]; b != nil {
		return b.id
	}
	return ""
}
