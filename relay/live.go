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
