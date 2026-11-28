package relay

import (
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/blobs"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
)

// Headers of /blob (docs/messaging.md, "Blobs").
const (
	// HeaderTotal: on the first PUT of a file, its whole size. Answered on GET and HEAD.
	HeaderTotal = "Blob-Total"
	// HeaderOffset: on a PUT, where its bytes go (the size the server has; 0 for the first). Answered on every PUT,
	// HEAD and GET as the size the server has now.
	HeaderOffset = "Blob-Offset"
	// HeaderComplete: "true" once a file has all its bytes or a clip its last segment.
	HeaderComplete = "Blob-Complete"
	// HeaderOpen: "true" on the first PUT of a file whose size isn't known yet (a video's preview uploaded while the
	// phone encodes it), in place of Blob-Total. Answered on GET and HEAD while it grows.
	HeaderOpen = "Blob-Open"
	// HeaderLast: "true" on the PUT that ends an open file.
	HeaderLast = "Blob-Last"
	// fileFollow is the longest a GET ?follow=1 waits for an open file that stops growing.
	fileFollow = 60 * time.Second
	// clipFollow is the longest a GET follows a clip that stops growing (its talker gone without a word).
	clipFollow = MaxBurst + lastSegmentWait
)

// MayRead says whether user may read blob m (mayRead), for the listing of a saved call's tracks.
func (r *Relay) MayRead(user string, m blobs.Meta) bool { return r.mayRead(user, m) }

// mayRead says whether user may read blob m: its maker, the other user of its one-to-one conversation, or a member of
// its group now. Blocks apply. A kept call's track is only for the people who were in that call (joinedCall).
func (r *Relay) mayRead(user string, m blobs.Meta) bool {
	if m.Kind == blobs.Track && !r.joinedCall(user, m) {
		return false
	}
	// A talk buffer is for the members it was kept for (still a member, not blocking the talker), and its talker.
	if m.Kind == blobs.TalkBuffer && user != m.Owner && !slices.Contains(m.Readers, user) {
		return false
	}
	switch {
	case user == m.Owner:
		return true
	case m.Group != "":
		g, ok := r.Groups.Get(m.Group)
		return ok && g.Member(user) && !r.Book.Blocked(user, m.Owner)
	default:
		return user == m.Peer && !r.Book.Blocked(user, m.Owner)
	}
}

// joinedCall says whether user was in the call whose track m is: one of their devices sent a stream that the recorder
// kept. 2026-11-22 (hen): a group member who didn't join that call, or joined the group later, may not download it,
// though they can't decrypt it either (they never had the call's key).
func (r *Relay) joinedCall(user string, m blobs.Meta) bool {
	if m.Track == nil || r.Blobs == nil {
		return false
	}
	for _, t := range r.Blobs.OfCall(m.Track.Call) {
		if identityUser(t.Track.Identity) == user {
			return true
		}
	}
	return false
}

// identityUser is the user of a LiveKit identity "user.device" (a user name may hold dots: the number is after the
// last).
func identityUser(identity string) string {
	if dot := strings.LastIndex(identity, "."); dot >= 0 {
		return identity[:dot]
	}
	return identity
}

func setBlobHeaders(w http.ResponseWriter, m blobs.Meta) {
	w.Header().Set(HeaderOffset, strconv.FormatInt(m.Size, 10))
	w.Header().Set(HeaderComplete, strconv.FormatBool(m.Complete))
	if m.Total > 0 {
		w.Header().Set(HeaderTotal, strconv.FormatInt(m.Total, 10))
	}
	if m.Open && !m.Complete {
		w.Header().Set(HeaderOpen, "true")
	}
}

// ServeBlob is /blob/<id>, behind identify (a certificate is required).
//
//   - PUT uploads a file (a voice message, an attachment, a shared picture's preview or original) for ?peer=<user> or
//     ?group=<id>, resumable: the first PUT gives Blob-Total (or Blob-Open: true, and the PUT with Blob-Last: true
//     ends it), and each PUT's Blob-Offset is where its bytes go. ?keep=media marks a shared original (media_days).
//   - HEAD answers how much the server has (Blob-Offset), so a broken upload can go on.
//   - GET reads a file once it is complete, from a byte offset with "Range: bytes=N-"; a clip is read while it grows:
//     its records (a 4-byte big-endian length, then a ClipSegment without its burst id) are sent as they arrive
//     until its last one. A file that isn't complete is 409, or with ?follow=1 is sent as it grows.
//   - DELETE: its maker deletes it (a shared item deleted for everyone, an upload given up).
func (r *Relay) ServeBlob(w http.ResponseWriter, req *http.Request) {
	user := auth.FromContext(req.Context())
	device, _ := r.Registry.Find(auth.SerialFromContext(req.Context()))
	if user == nil || device.DeviceNumber == 0 {
		http.Error(w, "only an enrolled device", http.StatusForbidden)
		return
	}
	id := strings.TrimPrefix(req.URL.Path, "/blob/")
	if !blobs.ValidID(id) {
		http.Error(w, "a blob id is 32 lowercase hex digits", http.StatusNotFound)
		return
	}
	m, exists := r.Blobs.Get(id)
	switch req.Method {
	case http.MethodPut:
		r.putBlob(w, req, store.Device{User: user.Name, Number: device.DeviceNumber}, id, m, exists)
	case http.MethodGet, http.MethodHead:
		if !exists || !r.mayRead(user.Name, m) {
			http.Error(w, "no such blob", http.StatusNotFound)
			return
		}
		setBlobHeaders(w, m)
		if req.Method == http.MethodHead {
			return
		}
		r.Blobs.MarkRead(id, user.Name)
		r.getBlob(w, req, m, user.Name)
	case http.MethodDelete:
		if !exists || m.Owner != user.Name || m.Kind != blobs.File {
			http.Error(w, "no such blob", http.StatusNotFound)
			return
		}
		r.Blobs.Delete(id)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE")
		http.Error(w, "GET, HEAD, PUT or DELETE", http.StatusMethodNotAllowed)
	}
}

func (r *Relay) putBlob(w http.ResponseWriter, req *http.Request, from store.Device, id string, m blobs.Meta, exists bool) {
	if !exists {
		peer, group := req.URL.Query().Get("peer"), req.URL.Query().Get("group")
		if (peer == "") == (group == "") {
			http.Error(w, "name ?peer=<user> or ?group=<id>", http.StatusBadRequest)
			return
		}
		if _, status, detail := r.conversation(from, peer, group); status != 0 {
			http.Error(w, status.String()+": "+detail, http.StatusForbidden)
			return
		}
		open := req.Header.Get(HeaderOpen) == "true"
		total, err := strconv.ParseInt(req.Header.Get(HeaderTotal), 10, 64)
		if err != nil && !open {
			http.Error(w, "the first PUT gives "+HeaderTotal+" or "+HeaderOpen, http.StatusBadRequest)
			return
		}
		keep := ""
		if req.URL.Query().Get("keep") == blobs.KeepMedia {
			keep = blobs.KeepMedia
		}
		err = r.Blobs.Create(blobs.Meta{ID: id, Kind: blobs.File, Owner: from.User, Peer: peer, Group: group,
			Total: total, Open: open, Keep: keep})
		if errors.Is(err, blobs.ErrTooLarge) {
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil && !errors.Is(err, blobs.ErrExists) {
			log.Printf("PUT /blob from %s.%d: %v", from.User, from.Number, err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		m, _ = r.Blobs.Get(id)
	}
	if m.Owner != from.User {
		http.Error(w, "no such blob", http.StatusNotFound)
		return
	}
	offset := int64(0)
	if text := req.Header.Get(HeaderOffset); text != "" {
		var err error
		if offset, err = strconv.ParseInt(text, 10, 64); err != nil || offset < 0 {
			http.Error(w, HeaderOffset+" is a byte offset", http.StatusBadRequest)
			return
		}
	}
	size, err := r.Blobs.Write(id, offset, req.Body, req.Header.Get(HeaderLast) == "true")
	m, _ = r.Blobs.Get(id)
	setBlobHeaders(w, m)
	switch {
	case err == nil, errors.Is(err, blobs.ErrComplete) && offset == size:
		w.WriteHeader(http.StatusOK)
	case errors.Is(err, blobs.ErrOffset), errors.Is(err, blobs.ErrComplete), errors.Is(err, blobs.ErrBusy):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, blobs.ErrTooLarge):
		http.Error(w, "more bytes than "+HeaderTotal, http.StatusRequestEntityTooLarge)
	default:
		// A broken upload: what arrived is kept, and HEAD says how much.
		log.Printf("PUT /blob/%s from %s.%d: %v", id, from.User, from.Number, err)
		http.Error(w, "upload broke off", http.StatusBadRequest)
	}
}

func (r *Relay) getBlob(w http.ResponseWriter, req *http.Request, m blobs.Meta, user string) {
	offset := int64(0)
	if text, ok := strings.CutPrefix(req.Header.Get("Range"), "bytes="); ok {
		start, _, _ := strings.Cut(text, "-")
		n, err := strconv.ParseInt(start, 10, 64)
		if err != nil || n < 0 || n > m.Size {
			http.Error(w, "a range is bytes=N- within the blob", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		offset = n
	}
	follow := req.URL.Query().Get("follow") == "1"
	if m.Kind == blobs.File && !m.Complete && !follow {
		http.Error(w, "the upload isn't complete", http.StatusConflict)
		return
	}
	f, err := r.Blobs.OpenData(m.ID)
	if err != nil {
		http.Error(w, "no such blob", http.StatusNotFound)
		return
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if m.Kind == blobs.File && m.Complete {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(m.Size-offset, 10))
		if offset > 0 {
			w.WriteHeader(http.StatusPartialContent)
		}
		io.Copy(w, f)
		return
	}
	if m.Kind == blobs.File {
		// ?follow=1 on a file still uploading: what is there, then each piece as it arrives, until it completes or
		// fileFollow passes with nothing new (the reader asks again from where it got to). Blob-Complete in the
		// headers was false; the reader knows it has it all when the body ends at the size HEAD then answers.
		w.Header().Set("Content-Type", "application/octet-stream")
		if offset > 0 {
			w.WriteHeader(http.StatusPartialContent)
		}
		r.follow(w, req, f, m, fileFollow, true)
		return
	}
	// A clip or a saved call's track: send what is there, then follow it until its last record.
	if m.Kind == blobs.Track || m.Kind == blobs.TalkBuffer {
		w.Header().Set("Content-Type", "application/vnd.ptt.track")
	} else {
		w.Header().Set("Content-Type", "application/vnd.ptt.clip")
	}
	if offset > 0 {
		w.WriteHeader(http.StatusPartialContent)
	}
	r.follow(w, req, f, m, clipFollow, false)
}

// follow sends blob m from f as it grows, until it completes, the reader goes or wait passes: from the start (a
// clip, bounded by its longest burst) or, with idle, since it last grew (a file still uploading).
func (r *Relay) follow(w http.ResponseWriter, req *http.Request, f io.Reader, m blobs.Meta, wait time.Duration, idle bool) {
	user := auth.FromContext(req.Context())
	rc := http.NewResponseController(w)
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		changed := r.Blobs.Changed(m.ID)
		if _, err := io.Copy(w, f); err != nil {
			return
		}
		rc.Flush()
		now, ok := r.Blobs.Get(m.ID)
		if !ok {
			return
		}
		if now.Complete {
			if _, err := io.Copy(w, f); err == nil && m.Kind == blobs.TalkBuffer && user != nil &&
				r.Blobs.ReadToEnd(m.ID, user.Name) {
				log.Printf("Talk buffer %s: read by all its members, deleted", m.ID)
			}
			return
		}
		select {
		case <-changed:
			if idle {
				deadline.Reset(wait)
			}
		case <-req.Context().Done():
			return
		case <-deadline.C:
			return
		}
	}
}
