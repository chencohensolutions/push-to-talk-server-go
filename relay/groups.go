package relay

import (
	"log"

	"github.com/chencohensolutions/push-to-talk-server-go/groups"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/push"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
	"google.golang.org/protobuf/proto"
)

func marshalFrame(e *pb.Envelope) ([]byte, error) {
	return proto.Marshal(&pb.Frame{Kind: &pb.Frame_Envelope{Envelope: e}})
}

// ShareGroup says whether a and c are both members of one group, so they may fetch each other's prekey bundles and
// send to each other (sender keys go over pairwise sessions) without being paired.
func (r *Relay) ShareGroup(a, c string) bool {
	return r.Groups != nil && r.Groups.ShareGroup(a, c)
}

// groupTargets is the active devices a group Send from device from goes to: every member's but the sending device,
// leaving out members who blocked the sender or whom it blocked, by user.
func (r *Relay) groupTargets(from store.Device, g groups.Group) (map[string]map[int]int, error) {
	out := map[string]map[int]int{}
	for _, user := range g.Members {
		if user != from.User && (r.Users.Find(user) == nil || r.Book.Blocked(from.User, user)) {
			continue
		}
		active, err := r.ActiveDevices(user)
		if err != nil {
			return nil, err
		}
		if user == from.User {
			delete(active, from.Number)
		}
		out[user] = active
	}
	return out, nil
}

// routeGroup checks and queues a group Send: one SENDER_KEY_MESSAGE, a copy of it for every device of groupTargets,
// which group_devices must name exactly.
func (r *Relay) routeGroup(from store.Device, send *pb.Send, result *pb.SendResult,
	refuse func(pb.SendResult_Status, string, ...any) *pb.SendResult) *pb.SendResult {
	var g groups.Group
	ok := false
	if r.Groups != nil {
		g, ok = r.Groups.Get(send.GetGroup())
	}
	if !ok || !g.Member(from.User) {
		return refuse(pb.SendResult_NOT_MEMBER, "%s isn't in group %s", from.User, send.GetGroup())
	}
	envelopes := send.GetEnvelopes()
	if len(envelopes) != 1 {
		return refuse(pb.SendResult_INVALID, "a group Send holds one envelope, not %d", len(envelopes))
	}
	e := envelopes[0]
	switch {
	case e.GetType() != pb.Envelope_SENDER_KEY_MESSAGE:
		return refuse(pb.SendResult_INVALID, "a group Send's envelope is a SENDER_KEY_MESSAGE, not %s", e.GetType())
	case e.GetRecipientUser() != "" || e.GetRecipientDevice() != 0:
		return refuse(pb.SendResult_INVALID, "a group Send's envelope names no recipient: group_devices does")
	case len(e.GetCiphertext()) == 0:
		return refuse(pb.SendResult_INVALID, "the envelope is empty")
	case len(e.GetCiphertext()) > MaxEnvelopeBytes:
		return refuse(pb.SendResult_TOO_LARGE, "the envelope is %d bytes, at most %d", len(e.GetCiphertext()), MaxEnvelopeBytes)
	}

	targets, err := r.groupTargets(from, g)
	if err != nil {
		log.Printf("Group Send from %s.%d: %v", from.User, from.Number, err)
		return refuse(pb.SendResult_STATUS_UNSPECIFIED, "server error")
	}
	// group_devices must be exactly the targets, each device once, with matching registration ids where given.
	stale := false
	named := map[store.Device]bool{}
	for _, list := range send.GetGroupDevices() {
		active, member := targets[list.GetUser()]
		for _, d := range list.GetDevices() {
			to := store.Device{User: list.GetUser(), Number: int(d.GetDeviceNumber())}
			if named[to] {
				return refuse(pb.SendResult_INVALID, "device %d of %s twice", to.Number, to.User)
			}
			named[to] = true
			registration, ok := active[to.Number]
			if !member || !ok || (d.GetRegistrationId() != 0 && int(d.GetRegistrationId()) != registration) {
				stale = true
			}
		}
	}
	var envelopesOut []*pb.Envelope
	var lists []*pb.UserDevices
	for _, user := range groups.Sorted(g.Members) {
		active, ok := targets[user]
		if !ok {
			continue
		}
		list := &pb.UserDevices{User: user}
		for _, n := range sortedNumbers(active) {
			list.Devices = append(list.Devices, &pb.ActiveDevice{DeviceNumber: uint32(n), RegistrationId: uint32(active[n])})
			to := store.Device{User: user, Number: n}
			if !named[to] {
				stale = true
			}
			envelopesOut = append(envelopesOut, &pb.Envelope{RecipientUser: user, RecipientDevice: uint32(n),
				Type: pb.Envelope_SENDER_KEY_MESSAGE, Ciphertext: e.GetCiphertext()})
		}
		lists = append(lists, list)
	}
	if stale {
		result.Devices = lists
		return refuse(pb.SendResult_STALE_DEVICES, "group_devices doesn't match the members' active devices")
	}
	if len(envelopesOut) == 0 {
		// Alone in the group with one phone: nothing to deliver.
		result.Status = pb.SendResult_ACCEPTED
		return result
	}
	return r.queueIn(from, g.ID, envelopesOut, result)
}

// AnnounceGroup queues a GROUP_CHANGED envelope about group g, made by user by, to every enrolled device of g's
// members and invited users and of also (users who just left or were taken out), but by's own device that made it.
func (r *Relay) AnnounceGroup(g groups.Group, by store.Device, also ...string) {
	now := r.Now()
	seen := map[string]bool{}
	for _, user := range append(g.Everyone(), also...) {
		if seen[user] {
			continue
		}
		seen[user] = true
		for _, n := range r.EnrolledDevices(user) {
			d := store.Device{User: user, Number: n}
			if d == by {
				continue
			}
			e := &pb.Envelope{Id: newID(), SenderUser: by.User, SenderDevice: uint32(by.Number), RecipientUser: user,
				RecipientDevice: uint32(n), Type: pb.Envelope_GROUP_CHANGED, Group: g.ID, ServerTimestamp: now.UnixMilli()}
			frame, _ := marshalFrame(e)
			if err := r.Store.Enqueue([]store.Queued{{To: d, ID: e.Id, Envelope: frame}},
				store.Limits{Envelopes: maxQueuedEnvelopes, Bytes: maxQueuedBytes}, now); err != nil {
				log.Printf("GROUP_CHANGED about %s for device %d of %s: %v", g.ID, n, user, err)
				continue
			}
			r.wake(d)
			r.pushQueued(d, push.Sync)
		}
	}
}

// removeFromGroups takes a removed user out of every group and deletes the groups it owned, telling the others.
func (r *Relay) removeFromGroups(user string) {
	if r.Groups == nil {
		return
	}
	changed, deleted, err := r.Groups.RemoveUser(user)
	if err != nil {
		log.Printf("Taking %s out of its groups: %v", user, err)
		return
	}
	by := store.Device{User: user}
	for _, g := range changed {
		r.AnnounceGroup(g, by)
	}
	for _, g := range deleted {
		r.AnnounceGroup(groups.Group{ID: g.ID}, by, g.Everyone()...)
	}
}
