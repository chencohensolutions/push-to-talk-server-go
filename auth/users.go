package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// User is one person on the server. The name is also the common name (CN) of every client certificate of the user's
// devices: enrollment signs CN=<name>.
type User struct {
	Name    string    `json:"name"`
	AddedAt time.Time `json:"added_at"`
	// The user's public identity key (libsignal's serialized IdentityKey, 33 bytes), set by the first device's
	// uploadPrekeys and changed only by replaceIdentityKey (docs/messaging.md). Empty until then.
	IdentityKey []byte `json:"identity_key,omitempty"`
	// When IdentityKey was last set.
	IdentityKeySetAt *time.Time `json:"identity_key_set_at,omitempty"`
	// The user's email, lower case: their identity (2026-11-22, hen), where `enroll-code` mails their enrollment link
	// when config.json has "gmail". Given by `user add <email>` or `user email`, or the one they joined with by an
	// invite (docs/authentication.md, "Invites"): the one the inviter typed, or for an invite to anyone the one the
	// friend gave, which nobody checked. Empty only for a user added by name before, or invited without an email. No
	// two users share one.
	Email string `json:"email,omitempty"`
	// The name the user gave for themselves (first and last name, any letters); shown to their contacts. Not unique:
	// the email and the keys tell people apart.
	DisplayName string `json:"display_name,omitempty"`
	// Who invited the user, when they joined by an invite.
	InvitedBy string `json:"invited_by,omitempty"`
	// The user hides their presence (online now, last seen) from their contacts, and so sees nobody's
	// (setPresenceVisible; docs/messaging.md, "Presence").
	PresenceHidden bool `json:"presence_hidden,omitempty"`
	// The user hides whether they can hear talk now (silent, Do Not Disturb, in a call) from their contacts
	// (setHearVisible; docs/messaging.md, "Can hear"). Shown unless set.
	HearHidden bool `json:"hear_hidden,omitempty"`
}

// ErrUserExists and ErrUnknownUser are what Add and Remove refuse.
var (
	ErrUserExists  = errors.New("user exists")
	ErrUnknownUser = errors.New("unknown user")
	// ErrEmailTaken is AddInvited with an email another user has.
	ErrEmailTaken = errors.New("another user has this email")
)

// maxUserNameLength is the longest name a user may have, in characters.
const maxUserNameLength = 32

// Users is users.json: the users devices may enroll as, written through a temp file and rename on every change.
// The server holds the only writer; `ptt-server user add` goes through its admin API.
type Users struct {
	mu    sync.RWMutex
	path  string
	users []User
}

// OpenUsers reads the users file at path; a missing file is no users yet.
func OpenUsers(path string) (*Users, error) {
	u := &Users{path: path}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return u, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &u.users); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	seen := map[string]bool{}
	for _, user := range u.users {
		if err := CheckUserName(user.Name); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if seen[user.Name] {
			return nil, fmt.Errorf("%s: user %q appears twice", path, user.Name)
		}
		seen[user.Name] = true
		if user.Email != "" {
			if seen["@"+user.Email] {
				return nil, fmt.Errorf("%s: email %q appears twice", path, user.Email)
			}
			seen["@"+user.Email] = true
		}
	}
	return u, nil
}

// CheckUserName refuses a name that can't be a certificate's CN and a file name on every platform: it is letters,
// digits, '.', '-' and '_', 1 to 32 of them, not starting with '.' or '-'.
func CheckUserName(name string) error {
	if name == "" {
		return errors.New("a user needs a name")
	}
	if utf8.RuneCountInString(name) > maxUserNameLength {
		return fmt.Errorf("user name %q is longer than %d characters", name, maxUserNameLength)
	}
	for i, r := range name {
		ok := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || ((r == '.' || r == '-') && i > 0)
		if !ok {
			return fmt.Errorf("user name %q: use letters, digits, '.', '-' and '_' only", name)
		}
	}
	return nil
}

// Find is the user with name, or nil.
func (u *Users) Find(name string) *User {
	u.mu.RLock()
	defer u.mu.RUnlock()
	for i := range u.users {
		if u.users[i].Name == name {
			user := u.users[i]
			return &user
		}
	}
	return nil
}

// List is every user, by name.
func (u *Users) List() []User {
	u.mu.RLock()
	defer u.mu.RUnlock()
	list := append([]User(nil), u.users...)
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// FindByEmail is the user whose email is email (any case), or nil.
func (u *Users) FindByEmail(email string) *User {
	email = strings.ToLower(strings.TrimSpace(email))
	u.mu.RLock()
	defer u.mu.RUnlock()
	for i := range u.users {
		if email != "" && u.users[i].Email == email {
			user := u.users[i]
			return &user
		}
	}
	return nil
}

// Add adds a user named name, added at at. A name that differs from an existing one only in case ("Hen" beside
// "hen") is refused too, so two users can't look the same.
func (u *Users) Add(name string, at time.Time) (User, error) {
	if err := CheckUserName(name); err != nil {
		return User{}, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.nameTaken(name) {
		return User{}, fmt.Errorf("%w: %s", ErrUserExists, name)
	}
	return u.add(User{Name: name, AddedAt: at.UTC()})
}

// nameTaken says whether a user has name, in any case. Callers hold mu.
func (u *Users) nameTaken(name string) bool {
	for _, user := range u.users {
		if strings.EqualFold(user.Name, name) {
			return true
		}
	}
	return false
}

// AddInvited adds a user who joined by an invite: with their email (lower case; ErrEmailTaken when another user has
// it; empty when they gave none), their display name and who invited them. The user name is made from the email's
// local part, or without an email from the display name, in a–z, 0–9, '.', '-' and '_' only (so it can't look like
// another in a different script), with a number added when it is taken: dana.cohen@example.com becomes dana.cohen,
// then dana.cohen2; "Dana Cohen" without an email becomes dana.cohen too.
func (u *Users) AddInvited(email, displayName, invitedBy string, at time.Time) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, user := range u.users {
		if email != "" && user.Email == email {
			return User{}, ErrEmailTaken
		}
	}
	base := NameFromEmail(email)
	if email == "" {
		base = NameFromDisplayName(displayName)
	}
	name := base
	for n := 2; u.nameTaken(name); n++ {
		suffix := fmt.Sprint(n)
		name = base[:min(len(base), maxUserNameLength-len(suffix))] + suffix
	}
	return u.add(User{Name: name, AddedAt: at.UTC(), Email: email, DisplayName: CleanDisplayName(displayName), InvitedBy: invitedBy})
}

// CheckEmail is email as users.json keeps it (trimmed, lower case), or an error when it isn't one plain address
// (name@domain, no display name, no spaces or line breaks).
func CheckEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || !strings.Contains(email[strings.LastIndex(email, "@")+1:], ".") ||
		strings.ContainsAny(email, " \t\r\n<>,;\"") {
		return "", fmt.Errorf("%q is not an email address", email)
	}
	return email, nil
}

// AddWithEmail adds a user by `ptt-server user add <email> [name]`: its email (CheckEmail; ErrEmailTaken when
// another user has it) and a name, made from the email by NameFromEmail when name is empty (with a number added
// when it is taken). A name given is checked like Add's.
func (u *Users) AddWithEmail(email, name string, at time.Time) (User, error) {
	email, err := CheckEmail(email)
	if err != nil {
		return User{}, err
	}
	if name != "" {
		if err := CheckUserName(name); err != nil {
			return User{}, err
		}
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.emailTaken(email, "") {
		return User{}, ErrEmailTaken
	}
	if name == "" {
		base := NameFromEmail(email)
		name = base
		for n := 2; u.nameTaken(name); n++ {
			suffix := fmt.Sprint(n)
			name = base[:min(len(base), maxUserNameLength-len(suffix))] + suffix
		}
	} else if u.nameTaken(name) {
		return User{}, fmt.Errorf("%w: %s", ErrUserExists, name)
	}
	return u.add(User{Name: name, AddedAt: at.UTC(), Email: email})
}

// SetEmail gives the user its email (`ptt-server user email <user> <email>`), for a user added before emails were
// its identity. ErrEmailTaken when another user has it.
func (u *Users) SetEmail(name, email string) (User, error) {
	email, err := CheckEmail(email)
	if err != nil {
		return User{}, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.emailTaken(email, name) {
		return User{}, ErrEmailTaken
	}
	for i := range u.users {
		if u.users[i].Name != name {
			continue
		}
		previous := u.users[i].Email
		u.users[i].Email = email
		if err := u.save(); err != nil {
			u.users[i].Email = previous
			return User{}, err
		}
		return u.users[i], nil
	}
	return User{}, fmt.Errorf("%w: %s", ErrUnknownUser, name)
}

// emailTaken says whether a user other than except has email. Callers hold mu.
func (u *Users) emailTaken(email, except string) bool {
	for _, user := range u.users {
		if user.Email == email && user.Name != except {
			return true
		}
	}
	return false
}

// NameFromEmail is a user name made from an email's local part: lower-case a–z, 0–9, '.', '-' and '_', starting with a
// letter or digit, at most 24 characters (room for a number); "user" when nothing is left.
func NameFromEmail(email string) string {
	local, _, _ := strings.Cut(strings.ToLower(email), "@")
	local, _, _ = strings.Cut(local, "+") // dana+talk@ is dana
	return nameFrom(local)
}

// NameFromDisplayName is a user name made from a display name by NameFromEmail's rule, its words joined by '.':
// "Dana Cohen" is dana.cohen; "user" when no a–z or digit is in it.
func NameFromDisplayName(displayName string) string {
	return nameFrom(strings.Join(strings.Fields(strings.ToLower(displayName)), "."))
}

func nameFrom(local string) string {
	var b strings.Builder
	for _, r := range local {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case (r == '.' || r == '-' || r == '_') && b.Len() > 0:
			b.WriteRune(r)
		}
	}
	name := strings.TrimRight(b.String(), ".-_")
	if len(name) > 24 {
		name = strings.TrimRight(name[:24], ".-_")
	}
	if name == "" {
		return "user"
	}
	return name
}

// maxDisplayNameLength is the longest display name, in characters.
const maxDisplayNameLength = 64

// CleanDisplayName drops control characters and spaces at the ends, and keeps at most 64 characters.
func CleanDisplayName(name string) string {
	name = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u202e' || r == '\u202d' {
			return -1
		}
		return r
	}, name))
	for utf8.RuneCountInString(name) > maxDisplayNameLength {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return name
}

// add appends user and saves. Callers hold mu.
func (u *Users) add(user User) (User, error) {
	u.users = append(u.users, user)
	if err := u.save(); err != nil {
		u.users = u.users[:len(u.users)-1]
		return User{}, err
	}
	return user, nil
}

// Remove takes the user out. Its devices' certificates are refused from then on (identify finds no user); the
// caller revokes them too, so a user added again by the same name doesn't get them back.
func (u *Users) Remove(name string) (User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i, user := range u.users {
		if user.Name != name {
			continue
		}
		previous := append([]User(nil), u.users...)
		u.users = append(u.users[:i:i], u.users[i+1:]...)
		if err := u.save(); err != nil {
			u.users = previous
			return User{}, err
		}
		return user, nil
	}
	return User{}, fmt.Errorf("%w: %s", ErrUnknownUser, name)
}

// ErrIdentityKeyMismatch is SetIdentityKey with a key that isn't the one the user already has.
var ErrIdentityKeyMismatch = errors.New("the user has another identity key")

// SetIdentityKey gives user its identity key. When the user already has one, the same key changes nothing, and
// another is refused with ErrIdentityKeyMismatch unless replace is set. It reports whether the key changed.
func (u *Users) SetIdentityKey(name string, key []byte, replace bool, at time.Time) (bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.users {
		if u.users[i].Name != name {
			continue
		}
		current := u.users[i].IdentityKey
		if bytes.Equal(current, key) {
			return false, nil
		}
		if len(current) > 0 && !replace {
			return false, ErrIdentityKeyMismatch
		}
		previous := u.users[i]
		at = at.UTC()
		u.users[i].IdentityKey = bytes.Clone(key)
		u.users[i].IdentityKeySetAt = &at
		if err := u.save(); err != nil {
			u.users[i] = previous
			return false, err
		}
		return true, nil
	}
	return false, fmt.Errorf("%w: %s", ErrUnknownUser, name)
}

// SetPresenceHidden hides or shows user's presence to their contacts.
func (u *Users) SetPresenceHidden(name string, hidden bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.users {
		if u.users[i].Name != name {
			continue
		}
		if u.users[i].PresenceHidden == hidden {
			return nil
		}
		u.users[i].PresenceHidden = hidden
		if err := u.save(); err != nil {
			u.users[i].PresenceHidden = !hidden
			return err
		}
		return nil
	}
	return fmt.Errorf("%w: %s", ErrUnknownUser, name)
}

// SetHearHidden hides or shows name's can-hear state from their contacts (setHearVisible).
func (u *Users) SetHearHidden(name string, hidden bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i := range u.users {
		if u.users[i].Name != name {
			continue
		}
		if u.users[i].HearHidden == hidden {
			return nil
		}
		u.users[i].HearHidden = hidden
		if err := u.save(); err != nil {
			u.users[i].HearHidden = !hidden
			return err
		}
		return nil
	}
	return fmt.Errorf("%w: %s", ErrUnknownUser, name)
}

// save writes the file through a temp file and rename. Callers hold mu.
func (u *Users) save() error {
	list := u.users
	if list == nil {
		list = []User{}
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return WriteAtomic(u.path, append(data, '\n'), 0o600)
}

// WriteAtomic writes data to path through a temp file in the same folder and a rename, so a crash never leaves a
// half-written file.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	_ = tmp.Chmod(perm) // CreateTemp makes it 0600; Windows keeps only the read-only bit
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
