package mail

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGoogle answers the token endpoint (an auth code once, then refresh tokens) and Gmail's send.
type fakeGoogle struct {
	t        *testing.T
	mu       sync.Mutex
	code     string
	verifier string
	refresh  int
	sent     []string
	revoked  bool
}

func idToken(email string) string {
	claims, _ := json.Marshal(map[string]any{"email": email, "email_verified": true})
	return "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
}

func (f *fakeGoogle) serve(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Form.Get("client_id") != "id-1" || r.Form.Get("client_secret") != "secret-1" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != f.code || r.Form.Get("code_verifier") == "" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			f.verifier = r.Form.Get("code_verifier")
			json.NewEncoder(w).Encode(map[string]any{"access_token": "a0", "expires_in": 3600,
				"refresh_token": "r-1", "id_token": idToken("Hen@Example.com")})
		case "refresh_token":
			if f.revoked || r.Form.Get("refresh_token") != "r-1" {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			f.refresh++
			json.NewEncoder(w).Encode(map[string]any{"access_token": "a1", "expires_in": 3600})
		}
	})
	mux.HandleFunc("/send", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer a1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body struct{ Raw string }
		json.NewDecoder(r.Body).Decode(&body)
		raw, err := base64.RawURLEncoding.DecodeString(body.Raw)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.sent = append(f.sent, string(raw))
		f.mu.Unlock()
		w.Write([]byte(`{"id":"m1"}`))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	oldAuth, oldToken, oldSend := googleAuthURL, googleTokenURL, gmailSendURL
	googleAuthURL, googleTokenURL, gmailSendURL = server.URL+"/auth", server.URL+"/token", server.URL+"/send"
	t.Cleanup(func() { googleAuthURL, googleTokenURL, gmailSendURL = oldAuth, oldToken, oldSend })
}

func writeClient(t *testing.T, dir string) string {
	path := filepath.Join(dir, "gmail-client.json")
	os.WriteFile(path, []byte(`{"installed":{"client_id":"id-1","client_secret":"secret-1"}}`), 0o600)
	return path
}

// TestGmailLoginAndSend signs in through the loopback flow and sends a code with the kept grant.
func TestGmailLoginAndSend(t *testing.T) {
	f := &fakeGoogle{t: t, code: "c-1"}
	f.serve(t)
	dir := t.TempDir()
	config := GmailConfig{ClientFile: writeClient(t, dir), TokenFile: filepath.Join(dir, "gmail.token"), FromName: "Talk"}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	email, err := Login(ctx, config, func(authURL string) {
		u, _ := url.Parse(authURL)
		q := u.Query()
		if q.Get("scope") != gmailScopes || q.Get("code_challenge_method") != "S256" || q.Get("access_type") != "offline" {
			t.Errorf("sign-in address asks for %v", q)
		}
		// The browser comes back to the loopback address with the code; a wrong state is refused first.
		go func() {
			bad, _ := http.Get(q.Get("redirect_uri") + "?code=c-1&state=wrong")
			if bad != nil && bad.StatusCode != http.StatusNotFound {
				t.Errorf("a wrong state got HTTP %d", bad.StatusCode)
			}
			http.Get(q.Get("redirect_uri") + "?code=c-1&state=" + url.QueryEscape(q.Get("state")))
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	if email != "hen@example.com" {
		t.Fatalf("signed in as %q", email)
	}
	saved, _ := os.ReadFile(config.TokenFile)
	if !strings.Contains(string(saved), `"refresh_token": "r-1"`) {
		t.Fatalf("token file: %s", saved)
	}

	sender, err := New(nil, &config)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := sender.Send("dana@example.com", "Talk code: 123456", "Your code is 123456\n"); err != nil {
			t.Fatal(err)
		}
	}
	if f.refresh != 1 {
		t.Fatalf("refreshed the access token %d times for two sends", f.refresh)
	}
	if len(f.sent) != 2 || !strings.Contains(f.sent[0], "From: \"Talk\" <hen@example.com>\r\n") ||
		!strings.Contains(f.sent[0], "To: dana@example.com\r\n") || !strings.Contains(f.sent[0], "Your code is 123456\r\n") {
		t.Fatalf("sent %q", f.sent)
	}
}

// TestGmailRevoked: a grant the owner revoked says to sign in again.
func TestGmailRevoked(t *testing.T) {
	f := &fakeGoogle{t: t, revoked: true}
	f.serve(t)
	dir := t.TempDir()
	config := GmailConfig{ClientFile: writeClient(t, dir), TokenFile: filepath.Join(dir, "gmail.token")}
	os.WriteFile(config.TokenFile, []byte(`{"email":"hen@example.com","refresh_token":"r-1"}`), 0o600)
	sender, err := New(nil, &config)
	if err != nil {
		t.Fatal(err)
	}
	err = sender.Send("dana@example.com", "s", "b")
	if err == nil || !strings.Contains(err.Error(), "mail-login") {
		t.Fatalf("revoked grant: %v", err)
	}
}

// TestNewChoosesTheSender: no token file is an error that names mail-login; gmail and smtp together are refused.
func TestNewChoosesTheSender(t *testing.T) {
	dir := t.TempDir()
	config := GmailConfig{ClientFile: writeClient(t, dir), TokenFile: filepath.Join(dir, "missing.token")}
	if _, err := New(nil, &config); err == nil || !strings.Contains(err.Error(), "mail-login") {
		t.Fatalf("missing token: %v", err)
	}
	if _, err := New(&Config{Host: "smtp.example.com", Username: "a@example.com"}, &config); err == nil {
		t.Fatal("gmail and smtp together were taken")
	}
	if s, err := New(nil, nil); err != nil {
		t.Fatal(err)
	} else if _, ok := s.(Log); !ok {
		t.Fatalf("no mail config gave %T", s)
	}
}
