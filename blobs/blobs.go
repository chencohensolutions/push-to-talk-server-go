// Package blobs keeps clips and attachments: files of ciphertext under the blobs folder (blob_dir), each beside a
// small JSON file that says who made it and for which conversation, so the server can tell who may read it. A clip
// grows while its burst lasts (one record per ClipSegment) and readers follow it until its last segment; a file
// (a voice message, an attachment, a shared picture's preview or original) is uploaded with PUT, resumably, and an
// open file grows while it is uploaded, readers following it. They are deleted blob_days after they were made; a
// shared original (Keep "media") media_days after it was made. The server never holds a key to them. See
// docs/messaging.md, "Talk" and "Blobs".
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
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
)

const (
	// DefaultMaxFileBytes is the largest file a device may upload (max_blob_mb): a shared video's original can be
	// gigabytes (2026-11-28, hen: share videos; it was 100 MB before).
	DefaultMaxFileBytes = 20 << 30
	// KeepMedia marks a shared original (PUT ?keep=media): kept media_days (2026-11-28, hen: 30) after it was
	// made, so whoever asks again, or the others in a group, get it without waking the sender's phone.
	KeepMedia = "media"
	// DefaultMinFreeBytes is the space a file upload must leave free on the blobs folder's disk (min_free_gb):
	// originals are kept 30 days and a video can be gigabytes, so the server's disk mustn't fill up (2026-11-28, hen).
	DefaultMinFreeBytes = 10 << 30
	// staleUpload is how long an incomplete file may go without a byte before the sweep deletes it.
	staleUpload = 48 * time.Hour
	// MaxClipBytes bounds one clip: 60 seconds of 24 kbit/s Opus is about 180 KB; with push-to-video, 60 seconds of
	// 1 Mbit/s video is about 7.5 MB.
	MaxClipBytes = 8 << 20
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
	// TalkBuffer: one push kept for the members who weren't in its talk room (package recorder, "Talk buffer"), in
	// a Track's record format; Readers may read it, and it goes once they all have (or after the buffer's hours).
	TalkBuffer Kind = "talk_buffer"
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
	// More conversations its maker shared it to (2026-11-28, hen: "share images between groups without doubling the
	// storage"): the same sealed file, readable in each.
	Shares []Conversation `json:"shares,omitempty"`
	// For a file: its whole size, given when the upload began. For a clip, or an open file: 0.
	Total int64 `json:"total,omitempty"`
	// An open file (2026-11-28): uploaded while it is being made (a video's preview as the phone encodes it), so its
	// size isn't known up front; the PUT with Blob-Last completes it, and readers may follow it until then.
	Open bool `json:"open,omitempty"`
	// "media" for a shared original (KeepMedia).
	Keep string `json:"keep,omitempty"`
	// When its last bytes arrived (a file): an upload left unfinished is deleted staleUpload after it.
	Modified time.Time `json:"modified_at,omitempty"`
	Size     int64     `json:"size"`
	Complete bool      `json:"complete"`
	Created  time.Time `json:"created_at"`
	// For a Track: the stream it holds. For a TalkBuffer too (Call is the talk room).
	Track *TrackInfo `json:"track,omitempty"`
	// For a TalkBuffer: the users it was kept for, and those who have read it to its end.
	Readers []string `json:"readers,omitempty"`
	Read    []string `json:"read,omitempty"`

	writing bool // an upload is going on
}

// Conversation is a one-to-one conversation (the other user) or a group.
type Conversation struct {
	Peer  string `json:"peer,omitempty"`
	Group string `json:"group,omitempty"`
}

// Conversations are every conversation m is readable in: the one it was made for, then those it was shared to.
func (m Meta) Conversations() []Conversation {
	out := make([]Conversation, 0, 1+len(m.Shares))
	if m.Peer != "" || m.Group != "" {
		out = append(out, Conversation{Peer: m.Peer, Group: m.Group})
	}
	return append(out, m.Shares...)
}

// MaxShares is how many conversations a file may be readable in.
const MaxShares = 64

var (
	ErrExists   = errors.New("a blob with this id exists")
	ErrNotFound = errors.New("no such blob")
	ErrBadID    = errors.New("a blob id is 32 hex digits")
	ErrTooLarge = errors.New("too large")
	ErrComplete = errors.New("the blob is complete")
	ErrOffset   = errors.New("the upload doesn't continue where the blob ends")
	ErrBusy     = errors.New("another upload of this blob is going on")
	ErrFull     = errors.New("the server's disk is too full")
)

// Store is the blobs folder.
type Store struct {
	dir string
	now func() time.Time
	// MaxFile is the largest file (max_blob_mb; DefaultMaxFileBytes). MinFree is the space a file upload must leave
	// free on the disk (min_free_gb; DefaultMinFreeBytes); 0 doesn't check. Free answers the space left (the disk's,
	// or a test's).
	MaxFile int64
	MinFree int64
	Free    func() int64

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
	s := &Store{dir: dir, now: now, MaxFile: DefaultMaxFileBytes, MinFree: DefaultMinFreeBytes, metas: map[string]*Meta{}, grew: map[string]chan struct{}{}}
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
			if m.Kind == File && !m.Complete {
				m.Modified = info.ModTime().UTC()
			}
		}
		s.metas[id] = &m
	}
	s.Free = func() int64 { return freeBytes(dir) }
	return s, nil
}

// roomFor says whether n more bytes leave MinFree on the disk (true when the disk can't be read).
func (s *Store) roomFor(n int64) bool {
	if s.MinFree <= 0 || s.Free == nil {
		return true
	}
	free := s.Free()
	return free < 0 || free-n >= s.MinFree
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
	if m.Kind == File && !m.Open && (m.Total <= 0 || m.Total > s.MaxFile) {
		return fmt.Errorf("%w: a file is 1 byte to %d MB", ErrTooLarge, s.MaxFile>>20)
	}
	if m.Open {
		m.Total = 0
	}
	if m.Kind == File && !s.roomFor(m.Total) {
		return ErrFull
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.metas[m.ID]; ok {
		return ErrExists
	}
	m.Size, m.Complete, m.Created = 0, false, s.now().UTC()
	m.Modified = m.Created
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
	case m.Kind != Clip && m.Kind != Track && m.Kind != TalkBuffer:
		return fmt.Errorf("blob %s isn't a clip or a track", id)
	case m.Complete:
		return ErrComplete
	case m.Kind == Clip && m.Size+4+int64(len(record)) > MaxClipBytes,
		(m.Kind == Track || m.Kind == TalkBuffer) && m.Size+4+int64(len(record)) > MaxTrackBytes:
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
// continues from the size HEAD or GET answers). It answers the file's size after. A file with a Total is complete
// with its last byte; an open file when last is set (Blob-Last) and all of r has arrived.
func (s *Store) Write(id string, offset int64, r io.Reader, last bool) (int64, error) {
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
	if m.Open && !s.roomFor(0) {
		s.mu.Unlock()
		return m.Size, ErrFull
	}
	m.writing = true
	total, open := m.Total, m.Open
	if open {
		total = s.MaxFile
	}
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
	m.Modified = s.now().UTC()
	if (!open && m.Size == total) || (open && last && err == nil) {
		m.Complete = true
		if open {
			m.Total = m.Size
		}
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

// Share makes file id readable in conversation c too, and starts its keeping time again (the new conversation gets
// it as long as a new upload would stay). Sharing it where it is already readable only starts the time again.
func (s *Store) Share(id string, c Conversation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.metas[id]
	if !ok || m.Kind != File {
		return ErrNotFound
	}
	if !slices.Contains(m.Conversations(), c) {
		if len(m.Shares) >= MaxShares {
			return ErrTooLarge
		}
		m.Shares = append(m.Shares, c)
	}
	m.Created = s.now()
	return s.saveMeta(m)
}

// Unshare takes file id out of conversation c; the file is deleted when no conversation is left. Answers whether it
// is still kept.
func (s *Store) Unshare(id string, c Conversation) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.metas[id]
	if !ok {
		return false
	}
	left := slices.DeleteFunc(m.Conversations(), func(x Conversation) bool { return x == c })
	if len(left) == 0 {
		s.remove(id)
		return false
	}
	m.Peer, m.Group, m.Shares = left[0].Peer, left[0].Group, left[1:]
	if len(m.Shares) == 0 {
		m.Shares = nil
	}
	s.saveMeta(m)
	return true
}

func (s *Store) remove(id string) {
	delete(s.metas, id)
	s.notify(id)
	os.Remove(s.dataPath(id))
	os.Remove(s.metaPath(id))
}

// Expire deletes the clips and attachments made before before, the shared originals (Keep "media") made before
// mediaBefore, and the files whose upload stopped staleUpload ago unfinished, and answers how many. A saved
// call's tracks are deleted on their own schedule (ExpireTracks), not here.
func (s *Store) Expire(before, mediaBefore time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	stale := s.now().Add(-staleUpload)
	n := 0
	for id, m := range s.metas {
		if m.Kind == Track || m.Kind == TalkBuffer || m.writing {
			continue
		}
		cutoff := before
		if m.Keep == KeepMedia {
			cutoff = mediaBefore
		}
		gone := m.Created.Before(cutoff) ||
			(m.Kind == File && !m.Complete && !m.Modified.IsZero() && m.Modified.Before(stale))
		if gone {
			s.remove(id)
			n++
		}
	}
	return n
}

// ExpireOrphans deletes the data files that have no meta (no .json beside them, so no blob the store knows) and
// were last written before before, and answers how many. They are left when a delete took the meta but not the
// data (on Windows a file a reader still has open can't be removed) or a server stopped mid-write; nothing reads
// them and Expire never sees them (2026-11-28: 28 such files on hen-server). Create makes the data file and its
// meta under the store's lock, so a file it is making is never taken for one.
func (s *Store) ExpireOrphans(before time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".blob")
		if !ok || !ValidID(id) || e.IsDir() {
			continue
		}
		if _, known := s.metas[id]; known {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.ModTime().Before(before) {
			continue
		}
		if os.Remove(s.dataPath(id)) == nil {
			n++
		}
	}
	return n
}

// ReadToEnd notes that user read TalkBuffer id to its end, and deletes it once every reader has; it answers whether
// it was deleted.
func (s *Store) ReadToEnd(id, user string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.metas[id]
	if !ok || m.Kind != TalkBuffer || !m.Complete {
		return false
	}
	if !slices.Contains(m.Read, user) {
		m.Read = append(m.Read, user)
		s.saveMeta(m)
	}
	for _, r := range m.Readers {
		if !slices.Contains(m.Read, r) {
			return false
		}
	}
	s.remove(id)
	return true
}

// ExpireTalkBuffers deletes the TalkBuffers made before before (livekit.talk_buffer_hours), and answers how many.
func (s *Store) ExpireTalkBuffers(before time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, m := range s.metas {
		if m.Kind == TalkBuffer && m.Created.Before(before) {
			s.remove(id)
			n++
		}
	}
	return n
}

// ExpireTracks deletes a saved call's Track blobs whose recording started before before, and answers how many
// (livekit.keep_call_days; 2026-11-23, hen: kept calls are no longer stored forever).
func (s *Store) ExpireTracks(before time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, m := range s.metas {
		if m.Kind == Track && m.Track != nil && m.Track.Recording.Before(before) {
			s.remove(id)
			n++
		}
	}
	return n
}
