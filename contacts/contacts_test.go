package contacts

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestPairsAreKeptInPairsJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pairs.json")
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	book, err := Open(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := book.Confirm("dana", "hen"); !errors.Is(err, ErrNoPairing) {
		t.Fatalf("confirming without a pairing: %v", err)
	}
	token, _, err := book.NewToken("hen")
	if err != nil {
		t.Fatal(err)
	}
	if !book.TokenValid(token, "hen") || book.TokenValid(token, "dana") {
		t.Fatal("TokenValid")
	}
	if used, _ := book.UseToken(token, "hen", "hen"); used {
		t.Fatal("a user used its own token")
	}
	if used, err := book.UseToken(token, "hen", "dana"); !used || err != nil {
		t.Fatalf("UseToken: %v %v", used, err)
	}
	if used, _ := book.UseToken(token, "hen", "dana"); used || book.TokenValid(token, "hen") {
		t.Fatal("a token worked twice")
	}
	if paired, err := book.Confirm("dana", "hen"); paired || err != nil {
		t.Fatalf("one confirmation: %v %v", paired, err)
	}
	if paired, err := book.Confirm("hen", "dana"); !paired || err != nil {
		t.Fatalf("both confirmations: %v %v", paired, err)
	}
	if err := book.Block("dana", "hen"); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, clock)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.Paired("hen", "dana") || !reopened.Blocked("hen", "dana") || len(reopened.Contacts("hen")) != 1 {
		t.Fatalf("reopened: %+v", reopened.data)
	}
	if err := reopened.RemoveUser("hen"); err != nil {
		t.Fatal(err)
	}
	if again, _ := Open(path, clock); again.Paired("hen", "dana") || again.Blocked("dana", "hen") {
		t.Fatalf("after removing hen: %+v", again.data)
	}
}

func TestTokensAndPairingsExpire(t *testing.T) {
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	book, _ := Open(filepath.Join(t.TempDir(), "pairs.json"), func() time.Time { return now })
	token, _, _ := book.NewToken("hen")
	now = now.Add(TokenTTL)
	if book.TokenValid(token, "hen") {
		t.Fatal("a token outlived its 10 minutes")
	}
	token, _, _ = book.NewToken("hen")
	book.UseToken(token, "hen", "dana")
	now = now.Add(PendingTTL + time.Minute)
	if _, err := book.Confirm("hen", "dana"); !errors.Is(err, ErrNoPairing) {
		t.Fatalf("confirming after a week: %v", err)
	}
	for range maxTokensPerUser {
		if _, _, err := book.NewToken("dana"); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := book.NewToken("dana"); !errors.Is(err, ErrTooManyTokens) {
		t.Fatalf("token %d: %v", maxTokensPerUser+1, err)
	}
}
