package livekit

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// With FAKE_LIVEKIT_LOG set, the test binary stands in for livekit-server: it notes LIVEKIT_KEYS and its arguments
// in that file and runs until killed.
func TestMain(m *testing.M) {
	if log := os.Getenv("FAKE_LIVEKIT_LOG"); log != "" {
		f, _ := os.OpenFile(log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		f.WriteString(os.Getenv("LIVEKIT_KEYS") + " " + strings.Join(os.Args[1:], " ") + "\n")
		f.Close()
		time.Sleep(time.Hour)
		return
	}
	os.Exit(m.Run())
}

func TestRunRestarts(t *testing.T) {
	log := t.TempDir() + "/starts"
	t.Setenv("FAKE_LIVEKIT_LOG", log)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	keys := Keys{Key: "APIkey", Secret: strings.Repeat("s", 32)}
	ctx, cancel := context.WithCancel(context.Background())
	restart := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() { Run(ctx, self, "livekit.yaml", keys, restart); close(done) }()
	starts := func(n int) []string {
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			data, _ := os.ReadFile(log)
			if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(data) > 0 && len(lines) >= n {
				return lines
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("LiveKit wasn't started %d times", n)
		return nil
	}
	if got := starts(1)[0]; got != "APIkey: "+keys.Secret+" --config livekit.yaml" {
		t.Fatalf("LiveKit was started as %q", got)
	}
	restart <- struct{}{}
	starts(2)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run didn't end with its context")
	}
}
