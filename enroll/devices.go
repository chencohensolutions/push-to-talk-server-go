package enroll

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxDeviceNumber is the highest device number: libsignal's device ids and LiveKit's participant identities
// (user.device) take a small number, and 127 keeps it to one byte wherever it is sent.
const MaxDeviceNumber = 127

// Device is one certificate issued through enrollment.
type Device struct {
	Serial        string     `json:"serial"`
	User          string     `json:"user"`
	Name          string     `json:"name"`
	KeyProtection string     `json:"key_protection"`
	RegisteredAt  time.Time  `json:"registered_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	// The certificate this one renewed (renewCertificate): the same device with a new key. That one is revoked the
	// first time this one is used.
	RenewedFrom string `json:"renewed_from,omitempty"`
	// The device's number among the user's devices, 1 to MaxDeviceNumber: libsignal's device id and the device part
	// of a LiveKit identity (docs/authentication.md, "Device numbers"). A renewed certificate keeps it.
	DeviceNumber int `json:"device_number"`
	// The device's FCM registration token (registerPush), and whether it shows notifications: the server sends
	// high-priority pushes only to devices that do (docs/messaging.md, "Push"). A renewed certificate keeps them;
	// revoking clears them, and a token FCM answers as gone is dropped.
	FCMToken             string `json:"fcm_token,omitempty"`
	NotificationsEnabled bool   `json:"notifications_enabled,omitempty"`
	// When the device last reached the server with this certificate (a request or its /ws closing), to the minute:
	// what Your devices shows (OwnDevice.lastSeenAt). Nil when it never did since this was kept (2026-11-22).
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

var (
	ErrDeviceNotFound = errors.New("device not found")
	// ErrTooManyDevices is an enrollment when every device number of the user is held by a device not revoked.
	ErrTooManyDevices = fmt.Errorf("the user has %d devices, the most there may be: revoke one first", MaxDeviceNumber)
)

// SerialString formats a certificate serial the way the registry stores it.
func SerialString(serial *big.Int) string {
	return fmt.Sprintf("%x", serial)
}

// Registry persists enrolled devices to a JSON file. Certificates that are not in the registry are not affected by
// it, unless the server takes enrolled certificates only (config.json "enrolled_only").
//
// Revoked serials are kept a second time, in a file of their own beside it (RevokedPath): a registry that is lost,
// reset or put back from an older copy then doesn't bring a revoked certificate back to life.
type Registry struct {
	mu      sync.RWMutex
	path    string
	devices []Device
	revoked map[string]time.Time // every serial ever revoked, also those the registry no longer lists
}

// RevokedPath is the file that keeps the revoked serials of the registry at path: devices.json's is
// devices.revoked.json.
func RevokedPath(path string) string {
	ext := filepath.Ext(path)
	return strings.TrimSuffix(path, ext) + ".revoked" + ext
}

func OpenRegistry(path string) (*Registry, error) {
	r := &Registry{path: path, revoked: map[string]time.Time{}}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(data, &r.devices); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	data, err = os.ReadFile(RevokedPath(path))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		// One that can't be read stops the server: going on without it would let revoked certificates in.
		if err := json.Unmarshal(data, &r.revoked); err != nil {
			return nil, fmt.Errorf("parse %s: %w", RevokedPath(path), err)
		}
	}
	// A registry put back without its revoked file: its revoked devices are taken into it now.
	missing := false
	for _, d := range r.devices {
		if _, ok := r.revoked[d.Serial]; d.RevokedAt != nil && !ok {
			r.revoked[d.Serial] = *d.RevokedAt
			missing = true
		}
	}
	if missing {
		if err := r.saveRevoked(); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// saveRevoked writes the revoked serials, through a temp file and rename. Callers hold mu (or are opening).
func (r *Registry) saveRevoked() error {
	data, err := json.MarshalIndent(r.revoked, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(RevokedPath(r.path), data)
}

// noteRevoked takes the registry's revoked devices into the second file. Callers hold mu.
func (r *Registry) noteRevoked() error {
	changed := false
	for _, d := range r.devices {
		if _, ok := r.revoked[d.Serial]; d.RevokedAt != nil && !ok {
			r.revoked[d.Serial] = *d.RevokedAt
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return r.saveRevoked()
}

// Add records device. A device without a number (DeviceNumber 0) gets the user's next free one (nextNumber), under
// the same lock, so two enrollments at once never share one. It returns the device as recorded.
func (r *Registry) Add(device Device) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if device.DeviceNumber == 0 {
		n, err := r.nextNumber(device.User)
		if err != nil {
			return Device{}, err
		}
		device.DeviceNumber = n
	}
	if device.DeviceNumber < 1 || device.DeviceNumber > MaxDeviceNumber {
		return Device{}, fmt.Errorf("device number %d isn't 1 to %d", device.DeviceNumber, MaxDeviceNumber)
	}
	r.devices = append(r.devices, device)
	if err := r.save(); err != nil {
		r.devices = r.devices[:len(r.devices)-1]
		return Device{}, err
	}
	return device, nil
}

// nextNumber is the lowest device number user never had; once all were had, the lowest no device of the user that
// isn't revoked holds. A number goes to a new device only when it must, so a contact's phone that still knows a
// revoked device by its number doesn't take a new one for it. Callers hold mu.
func (r *Registry) nextNumber(user string) (int, error) {
	used := map[int]bool{}
	held := map[int]bool{}
	for _, d := range r.devices {
		if d.User != user {
			continue
		}
		used[d.DeviceNumber] = true
		if d.RevokedAt == nil && !r.isRevokedLocked(d.Serial) {
			held[d.DeviceNumber] = true
		}
	}
	for n := 1; n <= MaxDeviceNumber; n++ {
		if !used[n] {
			return n, nil
		}
	}
	for n := 1; n <= MaxDeviceNumber; n++ {
		if !held[n] {
			return n, nil
		}
	}
	return 0, ErrTooManyDevices
}

// List returns the devices of user (all users when empty), oldest first.
func (r *Registry) List(user string) []Device {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []Device
	for _, d := range r.devices {
		if user == "" || d.User == user {
			result = append(result, d)
		}
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].RegisteredAt.Before(result[j].RegisteredAt) })
	return result
}

// Revoke revokes the certificate with serial only.
func (r *Registry) Revoke(serial string, at time.Time) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.devices {
		if r.devices[i].Serial != serial {
			continue
		}
		if r.devices[i].RevokedAt == nil {
			previous := r.devices[i]
			r.devices[i].RevokedAt = &at
			r.devices[i].FCMToken, r.devices[i].NotificationsEnabled = "", false
			if err := r.save(); err != nil {
				r.devices[i] = previous
				return Device{}, err
			}
		}
		return r.devices[i], nil
	}
	return Device{}, ErrDeviceNotFound
}

// RevokeDevice revokes the certificate with serial and every other certificate of the same device (its user and
// device number: what it renewed, and what renewed it), so a renewal in flight can't outlive the revocation. It
// returns the device with serial.
func (r *Registry) RevokeDevice(serial string, at time.Time) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	target := -1
	for i := range r.devices {
		if r.devices[i].Serial == serial {
			target = i
		}
	}
	if target < 0 {
		return Device{}, ErrDeviceNotFound
	}
	t := r.devices[target]
	return r.devices[target], r.revokeWhere(at, func(d Device) bool {
		return d.Serial == serial || (d.User == t.User && d.DeviceNumber == t.DeviceNumber)
	})
}

// RevokeUser revokes every certificate of user (user remove), and returns how many it revoked.
func (r *Registry) RevokeUser(user string, at time.Time) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, d := range r.devices {
		if d.User == user && d.RevokedAt == nil {
			n++
		}
	}
	return n, r.revokeWhere(at, func(d Device) bool { return d.User == user })
}

// revokeWhere revokes the devices match picks that aren't yet, and saves. Callers hold mu.
func (r *Registry) revokeWhere(at time.Time, match func(Device) bool) error {
	previous := append([]Device(nil), r.devices...)
	changed := false
	for i := range r.devices {
		if match(r.devices[i]) && r.devices[i].RevokedAt == nil {
			r.devices[i].RevokedAt = &at
			r.devices[i].FCMToken, r.devices[i].NotificationsEnabled = "", false
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := r.save(); err != nil {
		r.devices = previous
		return err
	}
	return nil
}

// SeenRounding is how finely LastSeenAt is kept: the registry is written at most once a minute per device.
const SeenRounding = time.Minute

// Seen notes that the device with serial reached the server at at. The file is written only when the time moved on
// by a minute, so a busy device doesn't rewrite it on every request.
func (r *Registry) Seen(serial string, at time.Time) error {
	at = at.UTC().Truncate(SeenRounding)
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.devices {
		if r.devices[i].Serial != serial {
			continue
		}
		if last := r.devices[i].LastSeenAt; last != nil && !at.After(*last) {
			return nil
		}
		previous := r.devices[i].LastSeenAt
		r.devices[i].LastSeenAt = &at
		if err := r.save(); err != nil {
			r.devices[i].LastSeenAt = previous
			return err
		}
		return nil
	}
	return ErrDeviceNotFound
}

// Find returns the device with this certificate serial.
func (r *Registry) Find(serial string) (Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, d := range r.devices {
		if d.Serial == serial {
			return d, true
		}
	}
	return Device{}, false
}

// UseRenewal revokes the certificate the device with serial renewed, if it isn't yet: the new one is in use. It
// reports the old serial when it revoked one.
func (r *Registry) UseRenewal(serial string, at time.Time) (string, error) {
	r.mu.RLock()
	var from string
	for _, d := range r.devices {
		if d.Serial == serial {
			from = d.RenewedFrom
		}
	}
	revoked := true
	for _, d := range r.devices {
		if from != "" && d.Serial == from {
			revoked = d.RevokedAt != nil
		}
	}
	r.mu.RUnlock()
	if from == "" || revoked {
		return "", nil
	}
	if _, err := r.Revoke(from, at); err != nil {
		return "", err
	}
	return from, nil
}

// SetPush records the FCM token of device number of user (every certificate of it not revoked: a renewal in flight
// too), and whether it shows notifications; an empty token removes it. Another device that had the same token loses
// it: a token is one app install, so that device is gone or was enrolled again.
func (r *Registry) SetPush(user string, number int, token string, notifications bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := append([]Device(nil), r.devices...)
	found := false
	for i := range r.devices {
		d := &r.devices[i]
		switch {
		case d.User == user && d.DeviceNumber == number:
			if d.RevokedAt != nil || r.isRevokedLocked(d.Serial) {
				continue
			}
			found = true
			d.FCMToken, d.NotificationsEnabled = token, notifications && token != ""
		case token != "" && d.FCMToken == token:
			d.FCMToken, d.NotificationsEnabled = "", false
		}
	}
	if !found {
		return ErrDeviceNotFound
	}
	if err := r.save(); err != nil {
		r.devices = previous
		return err
	}
	return nil
}

// DropPushToken removes token from the device that has it, after FCM answered that it is gone. It reports whether a
// device had it.
func (r *Registry) DropPushToken(token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := append([]Device(nil), r.devices...)
	dropped := false
	for i := range r.devices {
		if r.devices[i].FCMToken == token {
			r.devices[i].FCMToken, r.devices[i].NotificationsEnabled = "", false
			dropped = true
		}
	}
	if !dropped {
		return false, nil
	}
	if err := r.save(); err != nil {
		r.devices = previous
		return false, err
	}
	return true, nil
}

// PushTarget is the certificate of device number of user that pushes go to: not revoked, not expired at now, with
// an FCM token; the newest one when a renewal is in flight.
func (r *Registry) PushTarget(user string, number int, now time.Time) (Device, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var best Device
	found := false
	for _, d := range r.devices {
		if d.User != user || d.DeviceNumber != number || d.FCMToken == "" || d.RevokedAt != nil ||
			r.isRevokedLocked(d.Serial) || !now.Before(d.ExpiresAt) {
			continue
		}
		if !found || d.RegisteredAt.After(best.RegisteredAt) {
			best, found = d, true
		}
	}
	return best, found
}

func (r *Registry) IsRevoked(serial string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isRevokedLocked(serial)
}

// isRevokedLocked is IsRevoked for callers that hold mu.
func (r *Registry) isRevokedLocked(serial string) bool {
	if _, ok := r.revoked[serial]; ok {
		return true
	}
	for _, d := range r.devices {
		if d.Serial == serial {
			return d.RevokedAt != nil
		}
	}
	return false
}

// save writes through a temp file and rename, so a crash never leaves a half-written registry.
// Callers hold mu.
func (r *Registry) save() error {
	// The revoked serials first: a revocation is never in the registry alone.
	if err := r.noteRevoked(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r.devices, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(r.path, data)
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
