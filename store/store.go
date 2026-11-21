// Package store is the server's SQLite database (database_file, default ptt.db): the public keys each device
// uploads (registration id, signed prekey, last-resort Kyber prekey, one-time prekeys) and the message queue, one row
// per (recipient device, envelope). It holds no plaintext and no private key: envelopes are kept as the bytes the
// relay gives it. See docs/messaging.md.
//
// It uses modernc.org/sqlite, which is pure Go, so the server builds without cgo on every platform.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the open database. Its methods may be called from any goroutine.
type Store struct {
	db *sql.DB
}

// Device names one device: its user and its device number.
type Device struct {
	User   string
	Number int
}

const schema = `
CREATE TABLE IF NOT EXISTS device_keys (
	user TEXT NOT NULL,
	device INTEGER NOT NULL,
	registration_id INTEGER NOT NULL,
	signed_id INTEGER NOT NULL,
	signed_public BLOB NOT NULL,
	signed_signature BLOB NOT NULL,
	kyber_id INTEGER NOT NULL,
	kyber_public BLOB NOT NULL,
	kyber_signature BLOB NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (user, device)
);
CREATE TABLE IF NOT EXISTS one_time_prekeys (
	user TEXT NOT NULL,
	device INTEGER NOT NULL,
	kind INTEGER NOT NULL,
	key_id INTEGER NOT NULL,
	public BLOB NOT NULL,
	signature BLOB,
	PRIMARY KEY (user, device, kind, key_id)
);
CREATE TABLE IF NOT EXISTS queue (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	user TEXT NOT NULL,
	device INTEGER NOT NULL,
	id TEXT NOT NULL,
	envelope BLOB NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS queue_device ON queue (user, device, seq);
CREATE INDEX IF NOT EXISTS queue_id ON queue (user, device, id);
CREATE INDEX IF NOT EXISTS queue_created ON queue (created_at);
`

// Open opens (or makes) the database at path.
func Open(path string) (*Store, error) {
	// _txlock=immediate: a transaction takes the write lock when it begins, so two never deadlock upgrading theirs.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"+
		"&_pragma=synchronous(NORMAL)&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	// One connection: writes are serialised anyway, and every caller reads its rows to the end before the next query.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// --- Keys -------------------------------------------------------------------------------------------------------

// SignedKey is a public prekey with its id and the identity key's signature over it.
type SignedKey struct {
	ID        int
	Public    []byte
	Signature []byte
}

// Kind of a one-time prekey.
const (
	KindEC    = 0
	KindKyber = 1
)

// DeviceKeys is what a device keeps on the server so others can open a session with it.
type DeviceKeys struct {
	RegistrationID  int
	Signed          SignedKey
	KyberLastResort SignedKey
}

// Upload is one uploadPrekeys: the device's keys (nil keeps the ones stored) and one-time prekeys to add.
type Upload struct {
	RegistrationID  int
	Signed          *SignedKey
	KyberLastResort *SignedKey
	OneTimeEC       []SignedKey // Signature unused
	OneTimeKyber    []SignedKey
}

// ErrNoKeys is an upload without the signed and last-resort prekeys from a device that hasn't stored them yet.
var ErrNoKeys = errors.New("the first upload needs the signed prekey and the last-resort Kyber prekey")

// Upload stores a device's keys. A one-time prekey with an id already stored replaces it.
func (s *Store) Upload(d Device, u Upload, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	current, found, err := keysOf(tx, d)
	if err != nil {
		return err
	}
	if !found && (u.Signed == nil || u.KyberLastResort == nil) {
		return ErrNoKeys
	}
	current.RegistrationID = u.RegistrationID
	if u.Signed != nil {
		current.Signed = *u.Signed
	}
	if u.KyberLastResort != nil {
		current.KyberLastResort = *u.KyberLastResort
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO device_keys VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.User, d.Number, current.RegistrationID, current.Signed.ID, current.Signed.Public, current.Signed.Signature,
		current.KyberLastResort.ID, current.KyberLastResort.Public, current.KyberLastResort.Signature, now.UnixMilli()); err != nil {
		return err
	}
	for kind, keys := range map[int][]SignedKey{KindEC: u.OneTimeEC, KindKyber: u.OneTimeKyber} {
		for _, k := range keys {
			var signature []byte
			if kind == KindKyber {
				signature = k.Signature
			}
			if _, err := tx.Exec(`INSERT OR REPLACE INTO one_time_prekeys VALUES (?, ?, ?, ?, ?, ?)`,
				d.User, d.Number, kind, k.ID, k.Public, signature); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

type querier interface {
	QueryRow(query string, args ...any) *sql.Row
}

func keysOf(q querier, d Device) (DeviceKeys, bool, error) {
	var k DeviceKeys
	err := q.QueryRow(`SELECT registration_id, signed_id, signed_public, signed_signature, kyber_id, kyber_public,
		kyber_signature FROM device_keys WHERE user = ? AND device = ?`, d.User, d.Number).Scan(&k.RegistrationID,
		&k.Signed.ID, &k.Signed.Public, &k.Signed.Signature, &k.KyberLastResort.ID, &k.KyberLastResort.Public,
		&k.KyberLastResort.Signature)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceKeys{}, false, nil
	}
	return k, err == nil, err
}

// Keys is the device's stored keys; false when it hasn't uploaded any.
func (s *Store) Keys(d Device) (DeviceKeys, bool, error) { return keysOf(s.db, d) }

// KeyedDevices is every device of user that has uploaded its keys, with its registration id, by device number.
func (s *Store) KeyedDevices(user string) (map[int]int, error) {
	rows, err := s.db.Query(`SELECT device, registration_id FROM device_keys WHERE user = ?`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]int{}
	for rows.Next() {
		var device, registration int
		if err := rows.Scan(&device, &registration); err != nil {
			return nil, err
		}
		out[device] = registration
	}
	return out, rows.Err()
}

// Counts is how many one-time prekeys of each kind the server holds for d.
func (s *Store) Counts(d Device) (ec, kyber int, err error) {
	rows, err := s.db.Query(`SELECT kind, COUNT(*) FROM one_time_prekeys WHERE user = ? AND device = ? GROUP BY kind`,
		d.User, d.Number)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, n int
		if err := rows.Scan(&kind, &n); err != nil {
			return 0, 0, err
		}
		if kind == KindEC {
			ec = n
		} else {
			kyber = n
		}
	}
	return ec, kyber, rows.Err()
}

// Bundle is what another device needs to open a session with one device: its keys, a one-time EC prekey (nil when
// none is left) and a Kyber prekey, one-time when there is one, else the last-resort one.
type Bundle struct {
	Device          int
	Keys            DeviceKeys
	OneTimeEC       *SignedKey
	Kyber           SignedKey
	KyberLastResort bool
}

// TakeBundle is d's bundle, using up one one-time prekey of each kind (the lowest id). False when d has no keys.
func (s *Store) TakeBundle(d Device) (Bundle, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Bundle{}, false, err
	}
	defer tx.Rollback()
	keys, found, err := keysOf(tx, d)
	if err != nil || !found {
		return Bundle{}, false, err
	}
	b := Bundle{Device: d.Number, Keys: keys}
	take := func(kind int) (*SignedKey, error) {
		var k SignedKey
		err := tx.QueryRow(`SELECT key_id, public, signature FROM one_time_prekeys WHERE user = ? AND device = ? AND kind = ?
			ORDER BY key_id LIMIT 1`, d.User, d.Number, kind).Scan(&k.ID, &k.Public, &k.Signature)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec(`DELETE FROM one_time_prekeys WHERE user = ? AND device = ? AND kind = ? AND key_id = ?`,
			d.User, d.Number, kind, k.ID)
		return &k, err
	}
	if b.OneTimeEC, err = take(KindEC); err != nil {
		return Bundle{}, false, err
	}
	kyber, err := take(KindKyber)
	if err != nil {
		return Bundle{}, false, err
	}
	if kyber != nil {
		b.Kyber = *kyber
	} else {
		b.Kyber, b.KyberLastResort = keys.KyberLastResort, true
	}
	return b, true, tx.Commit()
}

// ForgetKeys deletes the keys of d (a revoked device), or of every device of d.User when d.Number is 0.
func (s *Store) ForgetKeys(d Device) error {
	where, args := deviceWhere(d)
	if _, err := s.db.Exec(`DELETE FROM device_keys WHERE `+where, args...); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM one_time_prekeys WHERE `+where, args...)
	return err
}

func deviceWhere(d Device) (string, []any) {
	if d.Number == 0 {
		return "user = ?", []any{d.User}
	}
	return "user = ? AND device = ?", []any{d.User, d.Number}
}

// KeyedUsers is every user that has keys stored, for the sweep that forgets revoked devices.
func (s *Store) KeyedUsers() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT user FROM device_keys UNION SELECT DISTINCT user FROM queue`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// --- Queue ------------------------------------------------------------------------------------------------------

// Queued is one envelope for one device.
type Queued struct {
	To       Device
	ID       string
	Envelope []byte
}

// QueueFull is Enqueue refusing: Device's queue already holds the most envelopes or bytes it may.
type QueueFull struct{ Device Device }

func (e QueueFull) Error() string {
	return fmt.Sprintf("the queue of device %d of %s is full", e.Device.Number, e.Device.User)
}

// Limits of one device's queue.
type Limits struct {
	Envelopes int
	Bytes     int64
}

// Enqueue queues every envelope, or none: when a device's queue would go past limits it returns QueueFull.
func (s *Store) Enqueue(envelopes []Queued, limits Limits, now time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	adding := map[Device]int64{}
	for _, e := range envelopes {
		adding[e.To] += int64(len(e.Envelope))
	}
	for d, size := range adding {
		var n int
		var bytes int64
		if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(LENGTH(envelope)), 0) FROM queue WHERE user = ? AND device = ?`,
			d.User, d.Number).Scan(&n, &bytes); err != nil {
			return err
		}
		if (limits.Envelopes > 0 && n >= limits.Envelopes) || (limits.Bytes > 0 && bytes+size > limits.Bytes) {
			return QueueFull{Device: d}
		}
	}
	for _, e := range envelopes {
		if _, err := tx.Exec(`INSERT INTO queue (user, device, id, envelope, created_at) VALUES (?, ?, ?, ?, ?)`,
			e.To.User, e.To.Number, e.ID, e.Envelope, now.UnixMilli()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Row is a queued envelope as read back, with its place in the queue.
type Row struct {
	Seq      int64
	ID       string
	Envelope []byte
}

// After is up to limit envelopes queued for d after seq, oldest first.
func (s *Store) After(ctx context.Context, d Device, seq int64, limit int) ([]Row, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, id, envelope FROM queue WHERE user = ? AND device = ? AND seq > ?
		ORDER BY seq LIMIT ?`, d.User, d.Number, seq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.Seq, &r.ID, &r.Envelope); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Ack deletes the envelopes with ids from d's queue. An id that isn't there (already acknowledged, or another
// device's) is passed over.
func (s *Store) Ack(d Device, ids []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM queue WHERE user = ? AND device = ? AND id = ?`, d.User, d.Number, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// QueueLength is how many envelopes wait for d.
func (s *Store) QueueLength(d Device) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM queue WHERE user = ? AND device = ?`, d.User, d.Number).Scan(&n)
	return n, err
}

// ForgetQueue deletes d's queue (a revoked device), or every queue of d.User when d.Number is 0.
func (s *Store) ForgetQueue(d Device) error {
	where, args := deviceWhere(d)
	_, err := s.db.Exec(`DELETE FROM queue WHERE `+where, args...)
	return err
}

// Expire deletes the envelopes queued before before, and says how many.
func (s *Store) Expire(before time.Time) (int64, error) {
	r, err := s.db.Exec(`DELETE FROM queue WHERE created_at < ?`, before.UnixMilli())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}
