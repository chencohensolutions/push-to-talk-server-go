package invite

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

// Ten wrong passcodes end an invite, even spread out so the address's limit (5 a minute) never stops them.
func TestTenWrongPasscodesEndTheInvite(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "invites.json"), c.now)
	if err != nil {
		t.Fatal(err)
	}
	users, _ := auth.OpenUsers(filepath.Join(dir, "users.json"))
	users.Add("hen", c.t)
	s := NewService(store, users, nil, nil, c.now)
	invite, code, passcode, err := s.Create("hen", "")
	if err != nil {
		t.Fatal(err)
	}
	wrong := "000000"
	if passcode == wrong {
		wrong = "111111"
	}
	for i := range maxPasscodeTries {
		found, rejection := s.find("192.0.2.1", code)
		if rejection != "" {
			t.Fatalf("try %d: %s", i, rejection)
		}
		if got := s.checkPasscode("192.0.2.1", found, wrong); got != RejectWrongPasscode {
			t.Fatalf("try %d: %s", i, got)
		}
		c.t = c.t.Add(time.Minute)
	}
	if _, rejection := s.find("192.0.2.1", code); rejection != RejectInvalidCode {
		t.Fatalf("after %d wrong passcodes: %q", maxPasscodeTries, rejection)
	}
	if got := s.checkPasscode("192.0.2.1", invite, passcode); got != "" {
		t.Fatalf("the right passcode: %s", got)
	}
}

// invites.json from before every invite had a passcode: one with an email keeps its code as the passcode; one
// without can't be redeemed (its friend would have needed an email from the server).
func TestInvitesFromBeforePasscodes(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "invites.json")
	old := `[
  {"id": "aaaa0001", "code_hash": "` + hashCode("withemail") + `", "invited_by": "hen", "email": "dana@example.com",
   "email_code_hash": "` + hashCode("aaaa0001/123456") + `", "created_at": "2026-11-21T12:00:00Z", "expires_at": "2026-11-28T12:00:00Z"},
  {"id": "aaaa0002", "code_hash": "` + hashCode("foranyone") + `", "invited_by": "hen",
   "created_at": "2026-11-21T12:00:00Z", "expires_at": "2026-11-28T12:00:00Z"}
]`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	found, ok := store.Find("withemail")
	if !ok || found.PasscodeHash != hashCode("aaaa0001/123456") || found.OldEmailCodeHash != "" {
		t.Fatalf("the invite with an email: %+v %v", found, ok)
	}
	if _, ok := store.Find("foranyone"); ok {
		t.Fatal("an old invite without a passcode was found")
	}
}
