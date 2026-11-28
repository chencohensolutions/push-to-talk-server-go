// Package relay routes envelopes between devices: who may reach whom (pairs, blocks, pairing tokens, the user's own
// devices), the check that a Send covers every active device, the queue in the store, and the /ws connections that
// deliver it. The server reads only the routing fields; the ciphertext is libsignal's and stays closed. See
// docs/messaging.md.
package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/chencohensolutions/push-to-talk-server-go/contacts"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
	"github.com/chencohensolutions/push-to-talk-server-go/groups"
	"github.com/chencohensolutions/push-to-talk-server-go/livekit"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
	"github.com/chencohensolutions/push-to-talk-server-go/push"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
	"google.golang.org/protobuf/proto"
)

const (
	// MaxEnvelopeBytes is the most ciphertext one envelope may carry. Clips and attachments go through /blob
	// (phase 5a), so a message is small.
	MaxEnvelopeBytes = 256 << 10
	// maxEnvelopesPerSend: one envelope for each device of the recipient and of the sender, 127 each.
	maxEnvelopesPerSend = 2 * enroll.MaxDeviceNumber
	// MaxFrameBytes is the largest frame a device may send on /ws; a bigger one closes the connection.
	MaxFrameBytes = 4 << 20
	// The most one device's queue holds; past it, a Send to the device is refused QUEUE_FULL.
	maxQueuedEnvelopes = 10000
	maxQueuedBytes     = 256 << 20
)

// Relay is the message routing of one server.
type Relay struct {
	Users    *auth.Users
	Registry *enroll.Registry
	Store    *store.Store
	Book     *contacts.Book
	// Who is in which group (groups.json); nil is no groups.
	Groups *groups.Book
	// How long an envelope no device acknowledged is kept (queue_days).
	QueueTTL time.Duration
	Now      func() time.Time

	// Clips and attachments (blob_dir).
	Blobs *blobs.Store
	// How long a blob is kept (blob_days).
	BlobTTL time.Duration
	// How long a shared original is kept (media_days).
	MediaTTL time.Duration
	// How long a saved call's tracks are kept after recording starts (livekit.keep_call_days); 0 keeps them.
	CallTTL time.Duration
	// How long a talk buffer is kept when not all its readers read it (livekit.talk_buffer_hours).
	TalkBufferTTL time.Duration
	// The LiveKit room API, to take cut-off devices out of rooms; nil without LiveKit.
	Live *livekit.Client

	// Wakes devices without a /ws through FCM (docs/messaging.md, "Push"); nil sends no pushes.
	Push *push.Pusher

	mu    sync.Mutex
	conns map[store.Device]*conn
	// The users with a device connected now, and when the others were last (Presence), since the server started.
	online   map[string]bool
	lastSeen map[string]time.Time
	// hear is what each online user's phone last said of whether they can hear talk (HearState).
	hear map[string]pb.Hear

	// Talk: the floor of each conversation held now, and the bursts whose clip is still open, by id.
	talkMu sync.Mutex
	floors map[string]*burst
	bursts map[string]*burst
	// Calls (phase 6) by id: their rooms and conversations.
	calls map[string]call
}

// New is a relay over these stores.
func New(users *auth.Users, registry *enroll.Registry, st *store.Store, book *contacts.Book, queueTTL time.Duration, now func() time.Time) *Relay {
	return &Relay{Users: users, Registry: registry, Store: st, Book: book, QueueTTL: queueTTL, Now: now,
		conns: map[store.Device]*conn{}, online: map[string]bool{}, lastSeen: map[string]time.Time{}, hear: map[string]pb.Hear{},
		floors: map[string]*burst{}, bursts: map[string]*burst{}, calls: map[string]call{}}
}

// Refusal is why the relay won't route between two users, named as SendResult.Status and the GraphQL error codes.
type Refusal string

const (
	NotPaired   Refusal = "NOT_PAIRED"
	Blocked     Refusal = "BLOCKED"
	UnknownUser Refusal = "UNKNOWN_USER"
)

func (r Refusal) Error() string {
	switch r {
	case NotPaired:
		return "not paired with this user"
	case Blocked:
		return "blocked"
	default:
		return "no such user"
	}
}

// --- Devices ----------------------------------------------------------------------------------------------------

// EnrolledDevices is the device numbers of user that have a certificate not revoked and not expired, by number.
func (r *Relay) EnrolledDevices(user string) []int {
	now := r.Now()
	var out []int
	for _, d := range r.Registry.List(user) {
		if d.DeviceNumber == 0 || r.Registry.IsRevoked(d.Serial) || !now.Before(d.ExpiresAt) || slices.Contains(out, d.DeviceNumber) {
			continue
		}
		out = append(out, d.DeviceNumber)
	}
	sort.Ints(out)
	return out
}

// ActiveDevices is the devices of user that may receive messages: enrolled (EnrolledDevices) and with their keys
// uploaded. It maps the device number to the registration id.
func (r *Relay) ActiveDevices(user string) (map[int]int, error) {
	keyed, err := r.Store.KeyedDevices(user)
	if err != nil {
		return nil, err
	}
	active := map[int]int{}
	for _, n := range r.EnrolledDevices(user) {
		if registration, ok := keyed[n]; ok {
			active[n] = registration
		}
	}
	return active, nil
}

func sortedNumbers(m map[int]int) []int {
	out := make([]int, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

// MayFetchBundles says whether caller may fetch target's prekey bundles: its own user, a contact or a member of a
// group caller is in (neither blocked the other), or with an unused pairing token of target (counted: a token allows
// a few fetches).
func (r *Relay) MayFetchBundles(caller, target, routingToken string) error {
	if r.Users.Find(target) == nil {
		return UnknownUser
	}
	if caller == target {
		return nil
	}
	if r.Book.Blocked(caller, target) {
		return Blocked
	}
	if r.Book.Paired(caller, target) || r.ShareGroup(caller, target) {
		return nil
	}
	if routingToken != "" && r.Book.TokenFetch(routingToken, target) {
		return nil
	}
	return NotPaired
}

// Bundles is a prekey bundle of every active device of target but skip, using up their one-time prekeys.
func (r *Relay) Bundles(target string, skip store.Device) ([]store.Bundle, error) {
	active, err := r.ActiveDevices(target)
	if err != nil {
		return nil, err
	}
	var out []store.Bundle
	for _, n := range sortedNumbers(active) {
		d := store.Device{User: target, Number: n}
		if d == skip {
			continue
		}
		b, ok, err := r.Store.TakeBundle(d)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, b)
		}
	}
	return out, nil
}

// --- Sending ----------------------------------------------------------------------------------------------------

func newID() string {
	raw := make([]byte, 16)
	rand.Read(raw)
	return hex.EncodeToString(raw)
}

// route checks and queues one Send from device from (Send, which also wakes the recipients), and answers what became
// of it.
func (r *Relay) route(from store.Device, send *pb.Send) *pb.SendResult {
	result := &pb.SendResult{ClientId: send.GetClientId()}
	refuse := func(status pb.SendResult_Status, format string, args ...any) *pb.SendResult {
		result.Status = status
		result.Detail = fmt.Sprintf(format, args...)
		log.Printf("Send from %s.%d refused: %s: %s", from.User, from.Number, status, result.Detail)
		return result
	}
	if send.GetGroup() != "" {
		return r.routeGroup(from, send, result, refuse)
	}
	envelopes := send.GetEnvelopes()
	if len(envelopes) == 0 {
		return refuse(pb.SendResult_INVALID, "no envelopes")
	}
	if len(envelopes) > maxEnvelopesPerSend {
		return refuse(pb.SendResult_INVALID, "%d envelopes, at most %d", len(envelopes), maxEnvelopesPerSend)
	}
	other := ""
	seen := map[store.Device]bool{}
	provisioning := false
	for i, e := range envelopes {
		to := store.Device{User: e.GetRecipientUser(), Number: int(e.GetRecipientDevice())}
		switch {
		case to.User == "" || to.Number == 0:
			return refuse(pb.SendResult_INVALID, "envelope %d names no recipient device", i)
		case len(e.GetCiphertext()) == 0:
			return refuse(pb.SendResult_INVALID, "envelope %d is empty", i)
		case len(e.GetCiphertext()) > MaxEnvelopeBytes:
			return refuse(pb.SendResult_TOO_LARGE, "envelope %d is %d bytes, at most %d", i, len(e.GetCiphertext()), MaxEnvelopeBytes)
		case to == from:
			return refuse(pb.SendResult_INVALID, "envelope %d is for the sending device", i)
		case seen[to]:
			return refuse(pb.SendResult_INVALID, "device %d of %s twice", to.Number, to.User)
		}
		seen[to] = true
		switch e.GetType() {
		case pb.Envelope_PREKEY_MESSAGE, pb.Envelope_MESSAGE, pb.Envelope_SENDER_KEY_MESSAGE:
		case pb.Envelope_PROVISIONING:
			provisioning = true
		default:
			return refuse(pb.SendResult_INVALID, "envelope %d has type %s, which a device can't send", i, e.GetType())
		}
		if to.User != from.User {
			if other != "" && other != to.User {
				return refuse(pb.SendResult_INVALID, "envelopes for %s and %s: one other user per Send", other, to.User)
			}
			other = to.User
		}
	}

	if provisioning {
		// Linking a phone: to one device of the sender's own user, enrolled, which may have no keys yet.
		e := envelopes[0]
		if len(envelopes) != 1 || other != "" {
			return refuse(pb.SendResult_INVALID, "a PROVISIONING envelope goes alone, to a device of the sender's user")
		}
		if !slices.Contains(r.EnrolledDevices(from.User), int(e.GetRecipientDevice())) {
			return refuse(pb.SendResult_UNKNOWN_USER, "device %d of %s isn't enrolled", e.GetRecipientDevice(), from.User)
		}
		return r.queue(from, envelopes, result, false)
	}

	token := ""
	if other != "" {
		if r.Users.Find(other) == nil {
			return refuse(pb.SendResult_UNKNOWN_USER, "no user %s", other)
		}
		if r.Book.Blocked(from.User, other) {
			return refuse(pb.SendResult_BLOCKED, "%s and %s", from.User, other)
		}
		if !r.Book.Paired(from.User, other) && send.GetPushKind() == pb.PushKind_PUSH_CALL {
			// 2026-11-22 (hen): a call invite rings only a contact. Group members who aren't contacts still exchange
			// one-to-one messages (the group's sender keys travel that way), but they call each other in the group.
			return refuse(pb.SendResult_NOT_PAIRED, "%s isn't a contact of %s: one-to-one calls are for contacts", other, from.User)
		}
		if !r.Book.Paired(from.User, other) && !r.ShareGroup(from.User, other) {
			// A pair request: every envelope for the recipient carries the same unused token of the recipient.
			for _, e := range envelopes {
				if e.GetRecipientUser() != other {
					continue
				}
				if token == "" {
					token = e.GetRoutingToken()
				}
				if e.GetRoutingToken() == "" || e.GetRoutingToken() != token {
					return refuse(pb.SendResult_NOT_PAIRED, "%s isn't a contact of %s and the envelopes carry no routing token of it", other, from.User)
				}
			}
			if !r.Book.TokenValid(token, other) {
				return refuse(pb.SendResult_NOT_PAIRED, "the routing token isn't one of %s's, or was used or expired", other)
			}
		}
	}

	// Every active device of the recipient, and every other active device of the sender, must get one.
	users := []string{from.User}
	if other != "" {
		users = append(users, other)
	}
	stale := false
	var lists []*pb.UserDevices
	for _, user := range users {
		active, err := r.ActiveDevices(user)
		if err != nil {
			log.Printf("Send from %s.%d: %v", from.User, from.Number, err)
			return refuse(pb.SendResult_STATUS_UNSPECIFIED, "server error")
		}
		if user == from.User {
			delete(active, from.Number)
		}
		list := &pb.UserDevices{User: user}
		for _, n := range sortedNumbers(active) {
			list.Devices = append(list.Devices, &pb.ActiveDevice{DeviceNumber: uint32(n), RegistrationId: uint32(active[n])})
		}
		lists = append(lists, list)
		covered := 0
		for _, e := range envelopes {
			if e.GetRecipientUser() != user {
				continue
			}
			registration, ok := active[int(e.GetRecipientDevice())]
			if !ok || (e.GetRecipientRegistrationId() != 0 && int(e.GetRecipientRegistrationId()) != registration) {
				stale = true
			}
			covered++
		}
		if covered != len(active) {
			stale = true
		}
	}
	if stale {
		result.Devices = lists
		return refuse(pb.SendResult_STALE_DEVICES, "the envelopes don't match the active devices")
	}
	if token != "" {
		used, err := r.Book.UseToken(token, other, from.User)
		if err != nil {
			log.Printf("Send from %s.%d: recording the pairing: %v", from.User, from.Number, err)
		}
		if !used {
			return refuse(pb.SendResult_NOT_PAIRED, "the routing token was used meanwhile")
		}
		log.Printf("Pair request from %s to %s, by a pairing token", from.User, other)
	}
	return r.queue(from, envelopes, result, send.GetEphemeral() && token == "")
}

// queue stores the envelopes of an accepted Send and wakes the recipients' connections; ephemeral ones only go to
// the connections open now.
func (r *Relay) queue(from store.Device, envelopes []*pb.Envelope, result *pb.SendResult, ephemeral bool) *pb.SendResult {
	return r.queueIn(from, "", envelopes, result, ephemeral)
}

// queueIn is queue for envelopes of a group Send (group is its id; "" for any other Send).
func (r *Relay) queueIn(from store.Device, group string, envelopes []*pb.Envelope, result *pb.SendResult, ephemeral bool) *pb.SendResult {
	now := r.Now()
	queued := make([]store.Queued, 0, len(envelopes))
	for _, e := range envelopes {
		out := &pb.Envelope{
			Id:              newID(),
			SenderUser:      from.User,
			SenderDevice:    uint32(from.Number),
			RecipientUser:   e.GetRecipientUser(),
			RecipientDevice: e.GetRecipientDevice(),
			Type:            e.GetType(),
			Ciphertext:      e.GetCiphertext(),
			ServerTimestamp: now.UnixMilli(),
			Group:           group,
		}
		frame, err := proto.Marshal(&pb.Frame{Kind: &pb.Frame_Envelope{Envelope: out}})
		if err != nil {
			result.Status = pb.SendResult_STATUS_UNSPECIFIED
			return result
		}
		queued = append(queued, store.Queued{To: store.Device{User: out.RecipientUser, Number: int(out.RecipientDevice)},
			ID: out.Id, Envelope: frame})
		result.EnvelopeIds = append(result.EnvelopeIds, out.Id)
	}
	if ephemeral {
		// Straight to the open connections, behind what they are sent already; nothing is stored.
		for _, q := range queued {
			r.liveBytes(q.To, q.Envelope)
		}
		result.Status = pb.SendResult_ACCEPTED
		return result
	}
	if err := r.Store.Enqueue(queued, store.Limits{Envelopes: maxQueuedEnvelopes, Bytes: maxQueuedBytes}, now); err != nil {
		result.EnvelopeIds = nil
		var full store.QueueFull
		if errors.As(err, &full) {
			result.Status = pb.SendResult_QUEUE_FULL
			result.Detail = full.Error()
			return result
		}
		log.Printf("Send from %s.%d: %v", from.User, from.Number, err)
		result.Status = pb.SendResult_STATUS_UNSPECIFIED
		result.Detail = "server error"
		return result
	}
	result.Status = pb.SendResult_ACCEPTED
	for _, q := range queued {
		r.wake(q.To)
	}
	return result
}

// Announce queues an envelope the server makes (IDENTITY_KEY_CHANGED, PAIRED) from about to every enrolled device
// of each user in to. A device whose queue is full misses it.
func (r *Relay) Announce(kind pb.Envelope_Type, about string, payload []byte, to ...string) {
	now := r.Now()
	for _, user := range to {
		for _, n := range r.EnrolledDevices(user) {
			e := &pb.Envelope{Id: newID(), SenderUser: about, RecipientUser: user, RecipientDevice: uint32(n), Type: kind,
				Ciphertext: payload, ServerTimestamp: now.UnixMilli()}
			frame, _ := proto.Marshal(&pb.Frame{Kind: &pb.Frame_Envelope{Envelope: e}})
			d := store.Device{User: user, Number: n}
			if err := r.Store.Enqueue([]store.Queued{{To: d, ID: e.Id, Envelope: frame}},
				store.Limits{Envelopes: maxQueuedEnvelopes, Bytes: maxQueuedBytes}, now); err != nil {
				log.Printf("%s about %s for device %d of %s: %v", kind, about, n, user, err)
				continue
			}
			r.wake(d)
			r.pushQueued(d, push.Sync)
		}
	}
}

// --- Revocation and the sweep -----------------------------------------------------------------------------------

// Revoked takes effect at once after a device of user was revoked, or user removed: their /ws connections close,
// and the keys and queues of devices that aren't enrolled any more are deleted. A removed user's pairs, blocks and
// tokens go too.
func (r *Relay) Revoked(user string) {
	exists := r.Users.Find(user) != nil
	enrolled := r.EnrolledDevices(user)
	r.mu.Lock()
	for d, c := range r.conns {
		if d.User == user && (!exists || r.Registry.IsRevoked(c.serial) || !slices.Contains(enrolled, d.Number)) {
			c.close(closeRevoked, "revoked")
			delete(r.conns, d)
		}
	}
	r.mu.Unlock()
	r.leaveRooms(user, exists, enrolled)
	forget := func(d store.Device) {
		r.Push.Forget(d)
		if err := r.Store.ForgetKeys(d); err != nil {
			log.Printf("Forgetting the keys of device %d of %s: %v", d.Number, d.User, err)
		}
		if err := r.Store.ForgetQueue(d); err != nil {
			log.Printf("Forgetting the queue of device %d of %s: %v", d.Number, d.User, err)
		}
	}
	if !exists {
		forget(store.Device{User: user})
		if err := r.Book.RemoveUser(user); err != nil {
			log.Printf("Forgetting the contacts of %s: %v", user, err)
		}
		r.removeFromGroups(user)
		return
	}
	numbers := map[int]bool{}
	for _, d := range r.Registry.List(user) {
		numbers[d.DeviceNumber] = true
	}
	keyed, err := r.Store.KeyedDevices(user)
	if err != nil {
		log.Printf("Reading the keys of %s: %v", user, err)
	}
	for n := range keyed {
		numbers[n] = true
	}
	for n := range numbers {
		if !slices.Contains(enrolled, n) {
			forget(store.Device{User: user, Number: n})
		}
	}
}

// orphanAge is how long a blob data file without a meta waits before the sweep deletes it.
const orphanAge = time.Hour

// Sweep deletes the envelopes older than QueueTTL, and what is kept for devices no longer enrolled.
func (r *Relay) Sweep() {
	if n, err := r.Store.Expire(r.Now().Add(-r.QueueTTL)); err != nil {
		log.Printf("Expiring the queue: %v", err)
	} else if n > 0 {
		log.Printf("Expired %d envelopes no device took in %v", n, r.QueueTTL)
	}
	if r.Blobs != nil && r.BlobTTL > 0 {
		if n := r.Blobs.Expire(r.Now().Add(-r.BlobTTL), r.mediaBefore()); n > 0 {
			log.Printf("Deleted %d clips and attachments older than %v", n, r.BlobTTL)
		}
	}
	if r.Blobs != nil {
		if n := r.Blobs.ExpireOrphans(r.Now().Add(-orphanAge)); n > 0 {
			log.Printf("Deleted %d blob files that had no meta", n)
		}
	}
	if r.Blobs != nil && r.CallTTL > 0 {
		if n := r.Blobs.ExpireTracks(r.Now().Add(-r.CallTTL)); n > 0 {
			log.Printf("Deleted %d kept-call tracks older than %v", n, r.CallTTL)
		}
	}
	if r.Blobs != nil && r.TalkBufferTTL > 0 {
		if n := r.Blobs.ExpireTalkBuffers(r.Now().Add(-r.TalkBufferTTL)); n > 0 {
			log.Printf("Deleted %d talk buffers older than %v", n, r.TalkBufferTTL)
		}
	}
	users, err := r.Store.KeyedUsers()
	if err != nil {
		log.Printf("Sweeping the keys: %v", err)
		return
	}
	for _, user := range users {
		r.Revoked(user)
	}
}

// Run sweeps at start and every hour until ctx ends.
func (r *Relay) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		r.Sweep()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// mediaBefore is when shared media made before is deleted: media_days ago, or never (the zero time) when media_days
// is -1, the default (2026-11-28, hen: "keep forever everything"; media_total_gb bounds it instead).
func (r *Relay) mediaBefore() time.Time {
	if r.MediaTTL > 0 {
		return r.Now().Add(-r.MediaTTL)
	}
	return time.Time{}
}
