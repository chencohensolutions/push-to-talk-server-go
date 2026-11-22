// Package blobs keeps clips and attachments: files of ciphertext under the blobs folder (blob_dir), each beside a
// small JSON file that says who made it and for which conversation, so the server can tell who may read it. A clip
// grows while its burst lasts (one record per ClipSegment) and readers follow it until its last segment; a file
// (a voice message, an attachment) is uploaded with PUT, resumably. Both are deleted blob_days after they were
// made. The server never holds a key to them. See docs/messaging.md, "Talk" and "Blobs".
package blobs

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
)

const (
	// MaxFileBytes is the largest file a device may upload (a voice message or an attachment).
	MaxFileBytes = 100 << 20
	// MaxClipBytes bounds one clip: 60 seconds of 24 kbit/s Opus is about 180 KB, so this is generous.
	MaxClipBytes = 4 << 20
	// MaxTrackBytes bounds one recorded track of a call: 4 hours of 1 Mbit/s video is about 1.8 GB.
	MaxTrackBytes = 2 << 30
)

// Kind is what a blob holds.
type Kind string

const (
	// Clip: the records of a talk burst, made by the server from ClipSegments.
	Clip Kind = "clip"
	// File: bytes a device uploaded as they are.
	File Kind = "file"
	// Track: one participant's audio or video in a saved call, as the server's recorder received it from LiveKit
	// (still encrypted end to end with the call's key): records of a timestamp, flags and one frame (package recorder).
	Track Kind = "track"
)

// TrackInfo is what a Track blob holds: whose stream, which, and when it began.
type TrackInfo struct {
	// The call's id, and the participant's LiveKit identity ("user.device").
	Call     string `json:"call"`
	Identity string `json:"identity"`
	// "audio" or "video", and the codec's MIME type (video/VP8, audio/opus).
	Media string `json:"media"`
	Codec string `json:"codec"`
	// When its first frame arrived; each record's timestamp counts from the recording's start (Recording).
	Started   time.Time `json:"started_at"`
	Recording time.Time `json:"recording_started_at"`
}

// Meta is what the server knows of a blob.
type Meta struct {
	ID    string `json:"id"`
	Kind  Kind   `json:"kind"`
	Owner string `json:"owner"` // the user who made it
	// The conversation: the other user of a one-to-one conversation, or a group's id.
	Peer  string `json:"peer,omitempty"`
	Group string `json:"group,omitempty"`
	// For a file: its whole size, given when the upload began. For a clip: 0.
	Total    int64     `json:"total,omitempty"`
	Size     int64     `json:"size"`
	Complete bool      `json:"complete"`
	Created  time.Time `json:"created_at"`
	// For a Track: the stream it holds.
	Track *TrackInfo `json:"track,omitempty"`

	writing bool // an upload is going on
}

var (
	ErrExists   = errors.New("a blob with this id exists")
	ErrNotFound = errors.New("no such blob")
	ErrBadID    = errors.New("a blob id is 32 hex digits")
	ErrTooLarge = errors.New("too large")
	ErrComplete = errors.New("the blob is complete")
	ErrOffset   = errors.New("the upload doesn't continue where the blob ends")
	ErrBusy     = errors.New("another upload of this blob is going on")
)

// Store is the blobs folder.
type Store struct {
	dir string
	now func() time.Time

	mu    sync.Mutex
	metas map[string]*Meta
	// grew is closed and replaced whenever a blob grows or completes, waking readers that follow it.
	grew map[string]chan struct{}
}

// ValidID says whether id is 32 lowercase hex digits.
func ValidID(id string) bool {
	if len(id) != 32 || strings.ToLower(id) != id {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

// Open reads the blobs folder at dir, making it when missing.
func Open(dir string, now func() time.Time) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, now: now, metas: map[string]*Meta{}, grew: map[string]chan struct{}{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !ValidID(id) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		var m Meta
		if err != nil || json.Unmarshal(data, &m) != nil || m.ID != id {
			continue
		}
		if info, err := os.Stat(s.dataPath(id)); err == nil {
			m.Size = info.Size() // what is on disk wins over the last saved size
		}
		s.metas[id] = &m
	}
	return s, nil
}

// Root is the blobs folder.
func (s *Store) Root() string { return s.dir }

func (s *Store) dataPath(id string) string { return filepath.Join(s.dir, id+".blob") }
func (s *Store) metaPath(id string) string { return filepath.Join(s.dir, id+".json") }

func (s *Store) saveMeta(m *Meta) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return auth.WriteAtomic(s.metaPath(m.ID), append(data, '\n'), 0o600)
}

// Create starts an empty blob.
func (s *Store) Create(m Meta) error {
	if !ValidID(m.ID) {
		return ErrBadID
	}
	if m.Kind == File && (m.Total <= 0 || m.Total > MaxFileBytes) {
		return fmt.Errorf("%w: a file is 1 byte to %d MB", ErrTooLarge, MaxFileBytes>>20)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.metas[m.ID]; ok {
		return ErrExists
	}
	m.Size, m.Complete, m.Created = 0, false, s.now().UTC()
	f, err := os.OpenFile(s.dataPath(m.ID), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	if err := s.saveMeta(&m); err != nil {
		os.Remove(s.dataPath(m.ID))
		return err
	}
	s.metas[m.ID] = &m
	return nil
}

// Get is blob id's meta.
func (s *Store) Get(id string) (Meta, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.metas[id]
	if !ok {
		return Meta{}, false
	}
	return *m, true
}

func (s *Store) notify(id string) {
	if ch, ok := s.grew[id]; ok {
		close(ch)
		delete(s.grew, id)
	}
}

// Changed is a channel closed the next time blob id grows or completes.
func (s *Store) Changed(id string) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.grew[id]
	if !ok {
		ch = make(chan struct{})
		s.grew[id] = ch
	}
	return ch
}

// AppendRecord adds one record to clip or track id: a 4-byte big-endian length, then the record. last completes it.
func (s *Store) AppendRecord(id string, record []byte, last bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.metas[id]
	switch {
	case !ok:
		return ErrNotFound
	case m.Kind != Clip && m.Kind != Track:
		return fmt.Errorf("blob %s isn't a clip or a track", id)
	case m.Complete:
		return ErrComplete
	case m.Kind == Clip && m.Size+4+int64(len(record)) > MaxClipBytes,
		m.Kind == Track && m.Size+4+int64(len(record)) > MaxTrackBytes:
		return ErrTooLarge
	}
	f, err := os.OpenFile(s.dataPath(id), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	data := binary.BigEndian.AppendUint32(nil, uint32(len(record)))
	_, err = f.Write(append(data, record...))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	m.Size += int64(len(data) + len(record))
	if last {
		m.Complete = true
		if err := s.saveMeta(m); err != nil {
			return err
		}
	}
	s.notify(id)
	return nil
}

// OfCall is the Track blobs of call, oldest first.
func (s *Store) OfCall(call string) []Meta {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Meta
	for _, m := range s.metas {
		if m.Kind == Track && m.Track != nil && m.Track.Call == call {
			out = append(out, *m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Track.Started.Equal(out[j].Track.Started) {
			return out[i].Track.Started.Before(out[j].Track.Started)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Finish completes clip or track id without a last record (its burst timed out or its talker dropped).
func (s *Store) Finish(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.metas[id]
	if !ok {
		return ErrNotFound
	}
	if m.Complete {
		return nil
	}
	m.Complete = true
	s.notify(id)
	return s.saveMeta(m)
}

// Write adds the bytes of r to file id at offset, which must be where the file ends now (an upload that broke off
// continues from the size HEAD or GET answers). It answers the file's size after.
func (s *Store) Write(id string, offset int64, r io.Reader) (int64, error) {
	s.mu.Lock()
	m, ok := s.metas[id]
	if !ok {
		s.mu.Unlock()
		return 0, ErrNotFound
	}
	if m.Kind != File {
		s.mu.Unlock()
		return 0, fmt.Errorf("blob %s isn't a file", id)
	}
	if m.Complete {
		s.mu.Unlock()
		return m.Size, ErrComplete
	}
	if offset != m.Size {
		size := m.Size
		s.mu.Unlock()
		return size, ErrOffset
	}
	if m.writing {
		s.mu.Unlock()
		return 0, ErrBusy
	}
	m.writing = true
	total := m.Total
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		m.writing = false
		s.mu.Unlock()
	}()
	f, err := os.OpenFile(s.dataPath(id), os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n, err := io.Copy(&offsetWriter{f: f, at: offset}, io.LimitReader(r, total-offset+1))
	s.mu.Lock()
	defer s.mu.Unlock()
	if offset+n > total {
		f.Truncate(offset)
		return offset, ErrTooLarge
	}
	m.Size = offset + n
	if m.Size == total {
		m.Complete = true
		if serr := s.saveMeta(m); err == nil {
			err = serr
		}
	}
	s.notify(id)
	return m.Size, err
}

type offsetWriter struct {
	f  *os.File
	at int64
}

func (w *offsetWriter) Write(p []byte) (int, error) {
	n, err := w.f.WriteAt(p, w.at)
	w.at += int64(n)
	return n, err
}

// OpenData opens blob id's bytes for reading.
func (s *Store) OpenData(id string) (*os.File, error) { return os.Open(s.dataPath(id)) }

// Delete removes blob id.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remove(id)
}

func (s *Store) remove(id string) {
	delete(s.metas, id)
	s.notify(id)
	os.Remove(s.dataPath(id))
	os.Remove(s.metaPath(id))
}

// Expire deletes the blobs made before before, and answers how many. A saved call's tracks are kept: they stay
// until a way to delete them is decided (2026-11-22, hen: "store the encrypted calls forever").
func (s *Store) Expire(before time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, m := range s.metas {
		if m.Kind != Track && m.Created.Before(before) {
			s.remove(id)
			n++
		}
	}
	return n
}
