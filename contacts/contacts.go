// Package contacts keeps who may reach whom: the pairs (two users who both confirmed, after one scanned the other's
// QR code), the pairings waiting for a confirmation, and the blocks, in pairs.json (pairs_file), written through a
// temp file and a rename on every change. It also holds the pairing tokens, in memory only. See docs/messaging.md.
package contacts

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	// TokenTTL is how long a pairing token lasts: the time to show a QR code and have it scanned.
	TokenTTL = 10 * time.Minute
	// maxTokensPerUser is how many unused pairing tokens one user may hold at once.
	maxTokensPerUser = 10
	// maxTokenFetches is how many prekeyBundles a token lets its holder fetch, so one QR code can't be used to drain
	// the owner's one-time prekeys.
	maxTokenFetches = 5
	// PendingTTL is how long a pairing that was introduced (its token used) waits for both confirmations.
	PendingTTL = 7 * 24 * time.Hour
)

// Pair is two users who both confirmed.
type Pair struct {
	Users [2]string `json:"users"` // by name
	Since time.Time `json:"since"`
}

// Pending is a pairing introduced by a pairing token, waiting for both users to call confirmPair.
type Pending struct {
	Users      [2]string `json:"users"`
	Introduced time.Time `json:"introduced_at"`
	Confirmed  []string  `json:"confirmed,omitempty"`
}

// Block is User refusing everything from Blocked.
type Block struct {
	User    string    `json:"user"`
	Blocked string    `json:"blocked"`
	At      time.Time `json:"at"`
}

type file struct {
	Pairs   []Pair    `json:"pairs"`
	Pending []Pending `json:"pending"`
	Blocks  []Block   `json:"blocks"`
}

type token struct {
	owner     string
	expiresAt time.Time
	fetches   int
}

// Book is pairs.json and the pairing tokens.
type Book struct {
	mu     sync.Mutex
	path   string
	data   file
	tokens map[[32]byte]*token
	now    func() time.Time
}

var (
	// ErrNoPairing is confirmPair for a user the caller wasn't introduced to by a pairing token, or too long ago.
	ErrNoPairing = errors.New("no pairing with this user is waiting: scan their QR code again")
	// ErrTooManyTokens is pairingToken from a user that holds maxTokensPerUser unused ones.
	ErrTooManyTokens = fmt.Errorf("at most %d pairing tokens at once; wait for one to expire", maxTokensPerUser)
)

// Open reads pairs.json at path; a missing file is no pairs yet.
func Open(path string, now func() time.Time) (*Book, error) {
	b := &Book{path: path, tokens: map[[32]byte]*token{}, now: now}
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

func ordered(a, b string) [2]string {
	if a > b {
		a, b = b, a
	}
	return [2]string{a, b}
}

func (b *Book) save() error {
	data, err := json.MarshalIndent(b.data, "", "  ")
	if err != nil {
		return err
	}
	return auth.WriteAtomic(b.path, append(data, '\n'), 0o600)
}

// change runs edit on a copy of the file's data and saves it; on an error nothing changes. Callers hold mu.
func (b *Book) change(edit func(*file)) error {
	previous := file{
		Pairs:   slices.Clone(b.data.Pairs),
		Pending: slices.Clone(b.data.Pending),
		Blocks:  slices.Clone(b.data.Blocks),
	}
	edit(&b.data)
	if err := b.save(); err != nil {
		b.data = previous
		return err
	}
	return nil
}

// Paired says whether a and b are paired.
func (b *Book) Paired(a, c string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pairIndex(a, c) >= 0
}

func (b *Book) pairIndex(a, c string) int {
	users := ordered(a, c)
	return slices.IndexFunc(b.data.Pairs, func(p Pair) bool { return p.Users == users })
}

// Blocked says whether either of a and c blocked the other.
func (b *Book) Blocked(a, c string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.blocks(a, c) || b.blocks(c, a)
}

func (b *Book) blocks(user, other string) bool {
	return slices.ContainsFunc(b.data.Blocks, func(x Block) bool { return x.User == user && x.Blocked == other })
}

// Contacts is every user paired with user, by name, and since when.
func (b *Book) Contacts(user string) []Pair {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Pair
	for _, p := range b.data.Pairs {
		if p.Users[0] == user || p.Users[1] == user {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return Other(out[i], user) < Other(out[j], user) })
	return out
}

// Other is the user of p that isn't user.
func Other(p Pair, user string) string {
	if p.Users[0] == user {
		return p.Users[1]
	}
	return p.Users[0]
}

// BlockedBy is the users user blocked, by name.
func (b *Book) BlockedBy(user string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, x := range b.data.Blocks {
		if x.User == user {
			out = append(out, x.Blocked)
		}
	}
	sort.Strings(out)
	return out
}

// NewToken is a pairing token for owner: 128 random bits, base64url, single use, for TokenTTL. Only its hash is kept.
func (b *Book) NewToken(owner string) (string, time.Time, error) {
	raw := make([]byte, 16)
	rand.Read(raw)
	text := base64.RawURLEncoding.EncodeToString(raw)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropExpiredTokens()
	held := 0
	for _, t := range b.tokens {
		if t.owner == owner {
			held++
		}
	}
	if held >= maxTokensPerUser {
		return "", time.Time{}, ErrTooManyTokens
	}
	expires := b.now().Add(TokenTTL)
	b.tokens[sha256.Sum256([]byte(text))] = &token{owner: owner, expiresAt: expires}
	return text, expires, nil
}

func (b *Book) dropExpiredTokens() {
	now := b.now()
	for k, t := range b.tokens {
		if !now.Before(t.expiresAt) {
			delete(b.tokens, k)
		}
	}
}

// TokenValid says whether text is an unused, unexpired pairing token of owner.
func (b *Book) TokenValid(text, owner string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropExpiredTokens()
	t, ok := b.tokens[sha256.Sum256([]byte(text))]
	return ok && t.owner == owner
}

// TokenFetch says whether text is an unused, unexpired pairing token of owner that may fetch prekeyBundles once more,
// and counts the fetch. It doesn't use the token up.
func (b *Book) TokenFetch(text, owner string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropExpiredTokens()
	t, ok := b.tokens[sha256.Sum256([]byte(text))]
	if !ok || t.owner != owner || t.fetches >= maxTokenFetches {
		return false
	}
	t.fetches++
	return true
}

// UseToken uses up text, a pairing token of owner, for one envelope from sender: it reports false when the token
// isn't one of owner's, is used or expired. Using it records a pairing waiting for both to confirm.
func (b *Book) UseToken(text, owner, sender string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dropExpiredTokens()
	key := sha256.Sum256([]byte(text))
	t, ok := b.tokens[key]
	if !ok || t.owner != owner || owner == sender {
		return false, nil
	}
	delete(b.tokens, key)
	users := ordered(owner, sender)
	now := b.now()
	return true, b.change(func(f *file) {
		f.Pending = slices.DeleteFunc(f.Pending, func(p Pending) bool {
			return p.Users == users || now.Sub(p.Introduced) > PendingTTL
		})
		f.Pending = append(f.Pending, Pending{Users: users, Introduced: now})
	})
}

// Confirm records user's confirmation of the pairing with other, and makes the pair once both confirmed. It reports
// whether they are paired now; ErrNoPairing when no pairing of theirs is waiting.
func (b *Book) Confirm(user, other string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pairIndex(user, other) >= 0 {
		return true, nil
	}
	users := ordered(user, other)
	now := b.now()
	i := slices.IndexFunc(b.data.Pending, func(p Pending) bool {
		return p.Users == users && now.Sub(p.Introduced) <= PendingTTL
	})
	if i < 0 {
		return false, ErrNoPairing
	}
	pending := b.data.Pending[i]
	if !slices.Contains(pending.Confirmed, user) {
		pending.Confirmed = append(slices.Clone(pending.Confirmed), user)
	}
	paired := slices.Contains(pending.Confirmed, other)
	return paired, b.change(func(f *file) {
		if paired {
			f.Pending = slices.Delete(f.Pending, i, i+1)
			f.Pairs = append(f.Pairs, Pair{Users: users, Since: now})
		} else {
			f.Pending[i] = pending
		}
	})
}

// Unpair removes the pair of user and other, and any pairing of theirs waiting. It reports whether there was one.
func (b *Book) Unpair(user, other string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	users := ordered(user, other)
	had := b.pairIndex(user, other) >= 0 ||
		slices.ContainsFunc(b.data.Pending, func(p Pending) bool { return p.Users == users })
	if !had {
		return false, nil
	}
	return true, b.change(func(f *file) {
		f.Pairs = slices.DeleteFunc(f.Pairs, func(p Pair) bool { return p.Users == users })
		f.Pending = slices.DeleteFunc(f.Pending, func(p Pending) bool { return p.Users == users })
	})
}

// Block records user blocking other. The pair, if any, is kept, but nothing is routed between them until user
// unblocks; a pairing waiting is dropped.
func (b *Book) Block(user, other string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.blocks(user, other) {
		return nil
	}
	users := ordered(user, other)
	now := b.now()
	return b.change(func(f *file) {
		f.Pending = slices.DeleteFunc(f.Pending, func(p Pending) bool { return p.Users == users })
		f.Blocks = append(f.Blocks, Block{User: user, Blocked: other, At: now})
	})
}

// Unblock takes user's block of other away, and reports whether there was one.
func (b *Book) Unblock(user, other string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.blocks(user, other) {
		return false, nil
	}
	return true, b.change(func(f *file) {
		f.Blocks = slices.DeleteFunc(f.Blocks, func(x Block) bool { return x.User == user && x.Blocked == other })
	})
}

// RemoveUser forgets every pair, pairing, block and token of user (user remove), so a user added again by the same
// name starts with no contacts.
func (b *Book) RemoveUser(user string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, t := range b.tokens {
		if t.owner == user {
			delete(b.tokens, k)
		}
	}
	has := func(users [2]string) bool { return users[0] == user || users[1] == user }
	return b.change(func(f *file) {
		f.Pairs = slices.DeleteFunc(f.Pairs, func(p Pair) bool { return has(p.Users) })
		f.Pending = slices.DeleteFunc(f.Pending, func(p Pending) bool { return has(p.Users) })
		f.Blocks = slices.DeleteFunc(f.Blocks, func(x Block) bool { return x.User == user || x.Blocked == user })
	})
}
