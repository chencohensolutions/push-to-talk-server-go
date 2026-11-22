// Package groups keeps who is in which group, in groups.json (groups_file), written through a temp file and a rename
// on every change. The server uses the list only to route: which devices a group Send goes to, who may fetch whose
// prekey bundles and send to whom (members who never paired), and, later, wake-ups and LiveKit tokens. A group's name
// and picture, and the members' identity keys, travel end to end in the owner's group changes; the phones trust
// those, never this list, so editing groups.json alone adds no reader (no member gives a sender key to a user the
// owner's devices didn't name). See docs/messaging.md, "Groups".
package groups

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
)

const (
	// MaxMembers is the most users a group holds, members and invited together (the plan's first build: 50).
	MaxMembers = 50
	// MaxOwned is the most groups one user may own.
	MaxOwned = 200
)

// Group is one group: its owner, the members who accepted (the owner is the first), and the users invited who haven't
// answered yet.
type Group struct {
	ID      string    `json:"id"` // 32 hex digits
	Owner   string    `json:"owner"`
	Members []string  `json:"members"`
	Invited []string  `json:"invited,omitempty"`
	Created time.Time `json:"created_at"`
}

// Member says whether user accepted (or owns) g.
func (g Group) Member(user string) bool { return slices.Contains(g.Members, user) }

// IsInvited says whether user is invited to g and hasn't answered.
func (g Group) IsInvited(user string) bool { return slices.Contains(g.Invited, user) }

// Everyone is the members and the invited.
func (g Group) Everyone() []string { return append(slices.Clone(g.Members), g.Invited...) }

func (g Group) clone() Group {
	g.Members = slices.Clone(g.Members)
	g.Invited = slices.Clone(g.Invited)
	return g
}

type file struct {
	Groups []Group `json:"groups"`
}

var (
	ErrNoGroup    = errors.New("no such group")
	ErrNotOwner   = errors.New("only the group's owner can do this")
	ErrFull       = fmt.Errorf("a group holds at most %d members", MaxMembers)
	ErrTooMany    = fmt.Errorf("at most %d groups per owner", MaxOwned)
	ErrNotInvited = errors.New("not invited to this group")
	ErrOwnerLeave = errors.New("the owner can't leave the group: delete it")
	ErrNotMember  = errors.New("not in this group")
)

// Book is groups.json.
type Book struct {
	mu   sync.Mutex
	path string
	data file
	now  func() time.Time
}

// Open reads groups.json at path; a missing file is no groups yet.
func Open(path string, now func() time.Time) (*Book, error) {
	b := &Book{path: path, now: now}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &b.data); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return b, nil
}

func (b *Book) save() error {
	data, err := json.MarshalIndent(b.data, "", "  ")
	if err != nil {
		return err
	}
	return auth.WriteAtomic(b.path, append(data, '\n'), 0o600)
}

// change runs edit on a copy of the groups and saves them; on an error nothing changes. Callers hold mu.
func (b *Book) change(edit func(*file)) error {
	previous := make([]Group, len(b.data.Groups))
	for i, g := range b.data.Groups {
		previous[i] = g.clone()
	}
	edit(&b.data)
	if err := b.save(); err != nil {
		b.data.Groups = previous
		return err
	}
	return nil
}

func (b *Book) index(id string) int {
	return slices.IndexFunc(b.data.Groups, func(g Group) bool { return g.ID == id })
}

// Get is the group id; false when there is none.
func (b *Book) Get(id string) (Group, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	i := b.index(id)
	if i < 0 {
		return Group{}, false
	}
	return b.data.Groups[i].clone(), true
}

// Of is the groups user is a member of or invited to, oldest first.
func (b *Book) Of(user string) []Group {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Group
	for _, g := range b.data.Groups {
		if g.Member(user) || g.IsInvited(user) {
			out = append(out, g.clone())
		}
	}
	return out
}

// ShareGroup says whether a and c are both members (not only invited) of one group.
func (b *Book) ShareGroup(a, c string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.ContainsFunc(b.data.Groups, func(g Group) bool { return g.Member(a) && g.Member(c) })
}

// Create is a new group owned by owner, its only member.
func (b *Book) Create(owner string) (Group, error) {
	raw := make([]byte, 16)
	rand.Read(raw)
	g := Group{ID: hex.EncodeToString(raw), Owner: owner, Members: []string{owner}, Created: b.now().UTC()}
	b.mu.Lock()
	defer b.mu.Unlock()
	owned := 0
	for _, x := range b.data.Groups {
		if x.Owner == owner {
			owned++
		}
	}
	if owned >= MaxOwned {
		return Group{}, ErrTooMany
	}
	return g.clone(), b.change(func(f *file) { f.Groups = append(f.Groups, g) })
}

// edit changes group id under the lock: do checks the group (a copy) and changes it, or answers an error and nothing
// changes. It answers the group as saved.
func (b *Book) edit(id string, do func(g *Group) error) (Group, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	i := b.index(id)
	if i < 0 {
		return Group{}, ErrNoGroup
	}
	g := b.data.Groups[i].clone()
	if err := do(&g); err != nil {
		return Group{}, err
	}
	return g.clone(), b.change(func(f *file) { f.Groups[i] = g })
}

// Invite records that owner invited user to group id. Inviting a member or someone invited already changes nothing.
func (b *Book) Invite(id, owner, user string) (Group, error) {
	return b.edit(id, func(g *Group) error {
		if g.Owner != owner {
			return ErrNotOwner
		}
		if g.Member(user) || g.IsInvited(user) {
			return nil
		}
		if len(g.Members)+len(g.Invited) >= MaxMembers {
			return ErrFull
		}
		g.Invited = append(g.Invited, user)
		return nil
	})
}

// Accept makes user, invited to group id, a member. A member accepting again changes nothing.
func (b *Book) Accept(id, user string) (Group, error) {
	return b.edit(id, func(g *Group) error {
		if g.Member(user) {
			return nil
		}
		if !g.IsInvited(user) {
			return ErrNotInvited
		}
		g.Invited = slices.DeleteFunc(g.Invited, func(u string) bool { return u == user })
		g.Members = append(g.Members, user)
		return nil
	})
}

// Leave takes user out of group id: a member leaving, or someone invited declining. The owner can't (ErrOwnerLeave).
func (b *Book) Leave(id, user string) (Group, error) {
	return b.edit(id, func(g *Group) error {
		if g.Owner == user {
			return ErrOwnerLeave
		}
		if !g.Member(user) && !g.IsInvited(user) {
			return ErrNotMember
		}
		g.Members = slices.DeleteFunc(g.Members, func(u string) bool { return u == user })
		g.Invited = slices.DeleteFunc(g.Invited, func(u string) bool { return u == user })
		return nil
	})
}

// Remove is owner taking user, a member or invited, out of group id.
func (b *Book) Remove(id, owner, user string) (Group, error) {
	return b.edit(id, func(g *Group) error {
		if g.Owner != owner {
			return ErrNotOwner
		}
		if user == owner {
			return ErrOwnerLeave
		}
		if !g.Member(user) && !g.IsInvited(user) {
			return ErrNotMember
		}
		g.Members = slices.DeleteFunc(g.Members, func(u string) bool { return u == user })
		g.Invited = slices.DeleteFunc(g.Invited, func(u string) bool { return u == user })
		return nil
	})
}

// Delete is owner deleting group id; it answers the group as it was.
func (b *Book) Delete(id, owner string) (Group, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	i := b.index(id)
	if i < 0 {
		return Group{}, ErrNoGroup
	}
	g := b.data.Groups[i].clone()
	if g.Owner != owner {
		return Group{}, ErrNotOwner
	}
	return g, b.change(func(f *file) { f.Groups = slices.Delete(f.Groups, i, i+1) })
}

// RemoveUser takes user out of every group (user remove) and deletes the groups user owned. It answers the groups
// that changed as they are now, and the ones deleted as they were.
func (b *Book) RemoveUser(user string) (changed, deleted []Group, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, g := range b.data.Groups {
		switch {
		case g.Owner == user:
			deleted = append(deleted, g.clone())
		case g.Member(user) || g.IsInvited(user):
			g = g.clone()
			g.Members = slices.DeleteFunc(g.Members, func(u string) bool { return u == user })
			g.Invited = slices.DeleteFunc(g.Invited, func(u string) bool { return u == user })
			changed = append(changed, g)
		}
	}
	if len(changed) == 0 && len(deleted) == 0 {
		return nil, nil, nil
	}
	err = b.change(func(f *file) {
		var kept []Group
		for _, g := range f.Groups {
			if g.Owner == user {
				continue
			}
			if i := slices.IndexFunc(changed, func(c Group) bool { return c.ID == g.ID }); i >= 0 {
				g = changed[i].clone()
			}
			kept = append(kept, g)
		}
		f.Groups = kept
	})
	return changed, deleted, err
}

// Sorted is users sorted, for answers that don't depend on the order of joining.
func Sorted(users []string) []string {
	out := slices.Clone(users)
	sort.Strings(out)
	return out
}
