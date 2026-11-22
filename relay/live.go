package relay

import (
	"context"
	"log"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/livekit"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
)

// TalkRoom is the LiveKit room of the conversation of device from with peer or group, after the same checks as
// talking there (conversation); the status says why not otherwise.
func (r *Relay) TalkRoom(from store.Device, peer, group string) (string, pb.SendResult_Status, string) {
	if (peer == "") == (group == "") {
		return "", pb.SendResult_INVALID, "name a peer or a group"
	}
	if _, status, detail := r.conversation(from, peer, group); status != 0 {
		return "", status, detail
	}
	if group != "" {
		return livekit.GroupRoom(group), 0, ""
	}
	return livekit.PairRoom(from.User, peer), 0, ""
}

// LeaveRoom takes every device of user out of room (taken out of a group, unpaired, blocked), in the background.
func (r *Relay) LeaveRoom(room, user string) {
	if r.Live == nil {
		return
	}
	var numbers []int
	for _, d := range r.Registry.List(user) {
		if !slices.Contains(numbers, d.DeviceNumber) {
			numbers = append(numbers, d.DeviceNumber)
		}
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, n := range numbers {
			if err := r.Live.Remove(ctx, room, livekit.Identity(user, n)); err != nil {
				log.Printf("LiveKit: taking device %d of %s out of %s: %v", n, user, room, err)
				return
			}
		}
	}()
}

// leaveRooms takes the devices of user that aren't enrolled any more (all of them for a removed user) out of every
// room, in the background (Revoked).
func (r *Relay) leaveRooms(user string, exists bool, enrolled []int) {
	if r.Live == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		n, err := r.Live.RemoveEverywhere(ctx, func(identity string) bool {
			dot := strings.LastIndex(identity, ".") // a user name may hold dots: the number is after the last
			if dot < 0 {
				return false
			}
			name, device := identity[:dot], identity[dot+1:]
			number, err := strconv.Atoi(device)
			return err == nil && name == user && (!exists || !slices.Contains(enrolled, number))
		})
		if err != nil {
			log.Printf("LiveKit: taking %s's cut-off devices out of the rooms: %v", user, err)
		} else if n > 0 {
			log.Printf("LiveKit: took %d cut-off devices of %s out of their rooms", n, user)
		}
	}()
}

// call is a call's room and its conversation, kept in memory so that leaving the conversation leaves its calls too.
type call struct {
	room    string
	group   string
	pair    string // floorKey of a one-to-one conversation
	created time.Time
}

// callTTL is how long a call's conversation is remembered (calls end long before; LiveKit closes an empty room).
const callTTL = 24 * time.Hour

// CallRoom is the room of call id in the conversation of from with peer or group, after the same checks as talking
// there. A call id is bound to its conversation by whoever names it first; another conversation can't take it.
func (r *Relay) CallRoom(from store.Device, id, peer, group string) (string, pb.SendResult_Status, string) {
	if _, status, detail := r.TalkRoom(from, peer, group); status != 0 {
		return "", status, detail
	}
	key := floorKey(from.User, peer, group)
	now := r.Now()
	r.talkMu.Lock()
	defer r.talkMu.Unlock()
	for k, c := range r.calls {
		if now.Sub(c.created) > callTTL {
			delete(r.calls, k)
		}
	}
	if c, ok := r.calls[id]; ok {
		if c.group != group || (group == "" && c.pair != key) {
			return "", pb.SendResult_INVALID, "this call id belongs to another conversation"
		}
		return c.room, 0, ""
	}
	c := call{room: livekit.CallRoom(id), group: group, created: now}
	if group == "" {
		c.pair = key
	}
	r.calls[id] = c
	return c.room, 0, ""
}

// LeaveCalls takes user's devices out of the calls of group, or of the pair of user and peer.
func (r *Relay) LeaveCalls(user, peer, group string) {
	key := floorKey(user, peer, group)
	r.talkMu.Lock()
	var rooms []string
	for _, c := range r.calls {
		if (group != "" && c.group == group) || (group == "" && c.pair == key) {
			rooms = append(rooms, c.room)
		}
	}
	r.talkMu.Unlock()
	for _, room := range rooms {
		r.LeaveRoom(room, user)
	}
}
