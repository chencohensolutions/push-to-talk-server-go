package relay

import (
	"context"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/contacts"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
)

// presenceRounding is how finely a contact's last seen is shown.
const presenceRounding = 5 * time.Minute

// Presence is what a contact sees of a user: connected now, or when last (zero when unknown or hidden).
type Presence struct {
	User     string
	Online   bool
	LastSeen time.Time
}

// presenceHidden says whether user hides their presence (and so sees nobody's).
func (r *Relay) presenceHidden(user string) bool {
	u := r.Users.Find(user)
	return u == nil || u.PresenceHidden
}

// maySee says whether viewer may see user's presence: contacts, neither blocked, neither hides it.
func (r *Relay) maySee(viewer, user string) bool {
	return viewer != user && r.Book.Paired(viewer, user) && !r.Book.Blocked(viewer, user) &&
		!r.presenceHidden(viewer) && !r.presenceHidden(user)
}

// Presences is the presence of each of users that is a contact of caller; the others are left out. A contact
// caller may not see (one of the two hides it) is offline with no last seen.
func (r *Relay) Presences(caller string, users []string) []Presence {
	var out []Presence
	seen := map[string]bool{}
	for _, user := range users {
		if seen[user] || user == caller || !r.Book.Paired(caller, user) || r.Book.Blocked(caller, user) {
			continue
		}
		seen[user] = true
		p := Presence{User: user}
		if !r.presenceHidden(caller) && !r.presenceHidden(user) {
			r.mu.Lock()
			p.Online = r.online[user]
			if !p.Online {
				p.LastSeen = r.lastSeen[user]
			}
			r.mu.Unlock()
		}
		out = append(out, p)
	}
	return out
}

// connected notes that a device of user connected: the first one makes the user online, and its contacts hear of
// it.
func (r *Relay) connected(user string) {
	r.mu.Lock()
	first := !r.online[user]
	r.online[user] = true
	r.mu.Unlock()
	if first {
		go r.announcePresence(&pb.Presence{User: user, Online: true})
	}
}

// disconnected notes that a device of user disconnected: when it was the last one, the user is offline from now,
// and its contacts hear of it.
func (r *Relay) disconnected(user string) {
	r.mu.Lock()
	for d := range r.conns {
		if d.User == user {
			r.mu.Unlock()
			return
		}
	}
	last := r.online[user]
	delete(r.online, user)
	seen := time.Now().UTC().Truncate(presenceRounding) // the wall clock: last seen is for people
	r.lastSeen[user] = seen
	r.mu.Unlock()
	if last {
		go r.announcePresence(&pb.Presence{User: user, LastSeen: seen.UnixMilli()})
	}
}

// announcePresence sends p to the connected devices of every contact of p.User that may see it.
func (r *Relay) announcePresence(p *pb.Presence) {
	if r.presenceHidden(p.User) {
		return
	}
	frame := &pb.Frame{Kind: &pb.Frame_Presence{Presence: p}}
	for _, pair := range r.Book.Contacts(p.User) {
		contact := contacts.Other(pair, p.User)
		if !r.maySee(contact, p.User) {
			continue
		}
		r.mu.Lock()
		var conns []*conn
		for d, c := range r.conns {
			if d.User == contact {
				conns = append(conns, c)
			}
		}
		r.mu.Unlock()
		for _, c := range conns {
			ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
			c.send(ctx, frame)
			cancel()
		}
	}
}
