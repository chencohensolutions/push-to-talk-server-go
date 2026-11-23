package relay

import (
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/push"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
)

// Send routes one Send from device from (route: the checks, then the queue), wakes the recipient devices that have
// no /ws open with the push the Send asked for, and answers what became of it.
func (r *Relay) Send(from store.Device, send *pb.Send) *pb.SendResult {
	result := r.route(from, send)
	if result.GetStatus() != pb.SendResult_ACCEPTED || send.GetEphemeral() {
		// An ephemeral Send wakes nobody: it went only to the connections open.
		return result
	}
	kind := PushKind(send.GetPushKind())
	var recipients []store.Device
	if send.GetGroup() != "" {
		// Accepted: group_devices is exactly the devices the copies went to.
		for _, list := range send.GetGroupDevices() {
			for _, d := range list.GetDevices() {
				recipients = append(recipients, store.Device{User: list.GetUser(), Number: int(d.GetDeviceNumber())})
			}
		}
	} else {
		for _, e := range send.GetEnvelopes() {
			recipients = append(recipients, store.Device{User: e.GetRecipientUser(), Number: int(e.GetRecipientDevice())})
		}
	}
	for _, to := range recipients {
		k := kind
		if to.User == from.User {
			// The sender's own devices show what their user sent: nothing to notify of.
			k = min(k, push.Sync)
		}
		r.pushQueued(to, k)
	}
	return result
}

// PushKind is the wake-up a Send's push_kind asks for; unset is Sync.
func PushKind(k pb.PushKind) push.Kind {
	switch k {
	case pb.PushKind_PUSH_NONE:
		return push.None
	case pb.PushKind_PUSH_MESSAGE:
		return push.Message
	case pb.PushKind_PUSH_TALK:
		return push.Talk
	case pb.PushKind_PUSH_CALL:
		return push.Call
	}
	return push.Sync
}

// pushQueued wakes d for an envelope just queued, unless it has /ws open (it got the envelope there).
func (r *Relay) pushQueued(d store.Device, kind push.Kind) {
	if !r.Push.On() || kind == push.None || r.Connected(d) {
		return
	}
	r.Push.Queued(d, kind)
}
