package blobs

import (
	"testing"
	"time"
)

// A kept call's tracks are deleted once their recording is older than keep_call_days, while recent ones and
// ordinary clips stay; blob_days (Expire) never touches tracks (2026-11-23, hen).
func TestExpireTracksDeletesOldKeptCallsOnly(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	s, err := Open(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	const (
		old    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		recent = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		clip   = "cccccccccccccccccccccccccccccccc"
	)
	mustCreate(t, s, Meta{ID: old, Kind: Track, Track: &TrackInfo{Call: "c1", Recording: now.Add(-8 * 24 * time.Hour)}})
	mustCreate(t, s, Meta{ID: recent, Kind: Track, Track: &TrackInfo{Call: "c2", Recording: now.Add(-2 * 24 * time.Hour)}})
	mustCreate(t, s, Meta{ID: clip, Kind: Clip})

	if n := s.ExpireTracks(now.Add(-7 * 24 * time.Hour)); n != 1 {
		t.Fatalf("ExpireTracks deleted %d, want 1", n)
	}
	if _, ok := s.Get(old); ok {
		t.Error("the week-old kept call should be gone")
	}
	if _, ok := s.Get(recent); !ok {
		t.Error("the two-day-old kept call should stay")
	}
	if _, ok := s.Get(clip); !ok {
		t.Error("a clip is not a kept call and should stay")
	}

	// blob_days (Expire) deletes the clip but never a kept call's tracks.
	if n := s.Expire(now.Add(time.Hour), now.Add(time.Hour)); n != 1 {
		t.Fatalf("Expire deleted %d, want 1 (the clip only)", n)
	}
	if _, ok := s.Get(recent); !ok {
		t.Error("Expire must not delete kept-call tracks")
	}
}

func mustCreate(t *testing.T, s *Store, m Meta) {
	t.Helper()
	if err := s.Create(m); err != nil {
		t.Fatalf("Create %s: %v", m.ID, err)
	}
}
