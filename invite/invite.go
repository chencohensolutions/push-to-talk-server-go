// Package invite lets an enrolled user invite a friend with one link (docs/authentication.md, "Invites"). The link
// holds an invite code, and a six-digit passcode goes beside it; the inviter's phone sends both, so the server sends
// no mail. A friend without the app on this server types the passcode and is made a user and enrolled in one step;
// a friend already enrolled here just redeems the link. Either way the answer is a pairing token of the inviter, so
// the friend's phone pairs with them as if it had scanned their QR code.
//
// The invites wait in invites.json (only the codes' hashes), so a server restart keeps them.
package invite

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/mail"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
)

const (
	// TTL is how long an invite link works: long enough to send it over a chat and have it opened.
	TTL = 7 * 24 * time.Hour
	// MaxPending is how many unused invites one user may have at once.
	MaxPending = 5
	// usedKept is how long a used or expired invite stays in the file, for `invites` and the log.
	usedKept = 7 * 24 * time.Hour
)

// Invite is one invite, as invites.json keeps it.
type Invite struct {
	// A short public id, to list and cancel it by; the code itself is only in the link.
	ID string `json:"id"`
	// The SHA-256 of the code, hex.
	CodeHash  string `json:"code_hash"`
	InvitedBy string `json:"invited_by"`
	// The email the invite is for, lower case; empty when it is for whoever opens it.
	Email string `json:"email,omitempty"`
	// The SHA-256 (hex) of "<id>/<six digits>": the passcode the inviter's phone sends beside the link.
	PasscodeHash string `json:"passcode_hash,omitempty"`
	// The same, as invites made before 2026-11-22 kept it (only for those with an email); Open moves it over.
	OldEmailCodeHash string     `json:"email_code_hash,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	ExpiresAt        time.Time  `json:"expires_at"`
	UsedBy           string     `json:"used_by,omitempty"`
	UsedAt           *time.Time `json:"used_at,omitempty"`
	Canceled         bool       `json:"canceled,omitempty"`
}

// Pending says whether the invite still works at now.
func (i Invite) Pending(now time.Time) bool {
	return i.UsedAt == nil && !i.Canceled && now.Before(i.ExpiresAt)
}

// Store is invites.json.
type Store struct {
	mu      sync.Mutex
	path    string
	invites []Invite
	now     func() time.Time
}

// Open reads invites.json at path; a missing file is no invites.
func Open(path string, now func() time.Time) (*Store, error) {
	s := &Store{path: path, now: now}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.invites); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for i := range s.invites {
		if s.invites[i].PasscodeHash == "" {
			s.invites[i].PasscodeHash = s.invites[i].OldEmailCodeHash
		}
		s.invites[i].OldEmailCodeHash = ""
	}
	return s, nil
}

// ErrTooMany is Create from a user with MaxPending unused invites.
var ErrTooMany = fmt.Errorf("at most %d invites at once: cancel one, or wait for one to be used or expire", MaxPending)

// Create makes an invite from by, for email when it isn't empty (lower-cased; NormalizeEmail checks it), and returns
// it with its code (128 random bits, base64url, 22 characters) and its passcode (six random digits), which the
// inviter's phone sends to the friend.
func (s *Store) Create(by, email string) (Invite, string, string, error) {
	raw := make([]byte, 16)
	rand.Read(raw)
	code := base64.RawURLEncoding.EncodeToString(raw)
	id := make([]byte, 4)
	rand.Read(id)
	now := s.now().UTC()
	passcode := newPasscode()
	invite := Invite{ID: hex.EncodeToString(id), CodeHash: hashCode(code), InvitedBy: by, Email: email,
		CreatedAt: now, ExpiresAt: now.Add(TTL)}
	invite.PasscodeHash = hashCode(invite.ID + "/" + passcode)
	s.mu.Lock()
	defer s.mu.Unlock()
	held := 0
	for _, i := range s.invites {
		if i.InvitedBy == by && i.Pending(now) {
			held++
		}
	}
	if held >= MaxPending {
		return Invite{}, "", "", ErrTooMany
	}
	if err := s.change(func(list *[]Invite) { *list = append(*list, invite) }); err != nil {
		return Invite{}, "", "", err
	}
	return invite, code, passcode, nil
}

// Drop stops invite id from working, whoever made it: one guessed at too often.
func (s *Store) Drop(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	at := slices.IndexFunc(s.invites, func(i Invite) bool { return i.ID == id })
	if at < 0 {
		return nil
	}
	return s.change(func(list *[]Invite) { (*list)[at].Canceled = true })
}

// List is by's pending invites, newest first.
func (s *Store) List(by string) []Invite {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Invite
	for _, i := range s.invites {
		if i.InvitedBy == by && i.Pending(now) {
			out = append(out, i)
		}
	}
	slices.Reverse(out)
	return out
}

// Cancel stops by's pending invite id from working. False if there was none.
func (s *Store) Cancel(by, id string) (bool, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	at := slices.IndexFunc(s.invites, func(i Invite) bool { return i.ID == id && i.InvitedBy == by && i.Pending(now) })
	if at < 0 {
		return false, nil
	}
	return true, s.change(func(list *[]Invite) { (*list)[at].Canceled = true })
}

// Find is the pending invite with code. One without a passcode (made without an email before every invite had one)
// can't be redeemed, and isn't found.
func (s *Store) Find(code string) (Invite, bool) {
	now := s.now()
	hash := hashCode(strings.TrimSpace(code))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, i := range s.invites {
		if subtle.ConstantTimeCompare([]byte(i.CodeHash), []byte(hash)) == 1 && i.Pending(now) && i.PasscodeHash != "" {
			return i, true
		}
	}
	return Invite{}, false
}

// Use marks the pending invite id used by user. False when it was used, canceled or expired meanwhile: an invite
// works once, even when two requests race.
func (s *Store) Use(id, user string) (bool, error) {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	at := slices.IndexFunc(s.invites, func(i Invite) bool { return i.ID == id && i.Pending(now) })
	if at < 0 {
		return false, nil
	}
	return true, s.change(func(list *[]Invite) {
		(*list)[at].UsedBy = user
		(*list)[at].UsedAt = &now
	})
}

// change edits the list, drops invites that ended long ago, and saves; on an error nothing changes. Callers hold mu.
func (s *Store) change(edit func(*[]Invite)) error {
	previous := slices.Clone(s.invites)
	edit(&s.invites)
	cutoff := s.now().Add(-usedKept)
	s.invites = slices.DeleteFunc(s.invites, func(i Invite) bool {
		ended := i.ExpiresAt
		if i.UsedAt != nil {
			ended = *i.UsedAt
		}
		return ended.Before(cutoff)
	})
	data, err := json.MarshalIndent(s.invites, "", "  ")
	if err == nil {
		err = auth.WriteAtomic(s.path, append(data, '\n'), 0o600)
	}
	if err != nil {
		s.invites = previous
	}
	return err
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// ErrInvalidEmail is NormalizeEmail of something that isn't an email address.
var ErrInvalidEmail = errors.New("not an email address")

// NormalizeEmail is email trimmed and lower-cased, when it is one plain address (no name, no angle brackets) with a
// dot in its domain.
func NormalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || len(email) > 254 {
		return "", ErrInvalidEmail
	}
	_, domain, _ := strings.Cut(email, "@")
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", ErrInvalidEmail
	}
	return email, nil
}

// newPasscode is six random digits.
func newPasscode() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1_000_000))
	return fmt.Sprintf("%06d", n.Int64())
}
