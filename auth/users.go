package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
}

// ErrUserExists and ErrUnknownUser are what Add and Remove refuse.
var (
	ErrUserExists  = errors.New("user exists")
	ErrUnknownUser = errors.New("unknown user")
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

// Add adds a user named name, added at at.
func (u *Users) Add(name string, at time.Time) (User, error) {
	if err := CheckUserName(name); err != nil {
		return User{}, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, user := range u.users {
		if user.Name == name {
			return User{}, fmt.Errorf("%w: %s", ErrUserExists, name)
		}
	}
	user := User{Name: name, AddedAt: at.UTC()}
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
