package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/mail"
)

// fakeMail keeps what the server mails.
type fakeMail struct {
	mu   sync.Mutex
	sent []struct{ to, subject, body string }
}

func (f *fakeMail) Send(to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, struct{ to, subject, body string }{to, subject, body})
	return nil
}

// newMailEnv is a server with "gmail" in config.json, whose mail goes to a fakeMail.
func newMailEnv(t *testing.T) (*testEnv, *fakeMail) {
	env := newTestEnv(t, func(c *auth.AppConfig) {
		dir := filepath.Dir(c.UsersFile)
		c.Gmail = &mail.GmailConfig{ClientFile: filepath.Join(dir, "gmail-client.json"), TokenFile: filepath.Join(dir, "gmail.token")}
	})
	if env.server.mail != nil {
		t.Fatal("a server without mail-login's token can send mail")
	}
	f := &fakeMail{}
	env.server.mail = f
	return env, f
}

// TestEnrollmentLinksAreMailed: with gmail on, a user is added by email, enroll-code mails the link to that address
// and returns no code, and the mailed link enrolls the phone.
func TestEnrollmentLinksAreMailed(t *testing.T) {
	env, f := newMailEnv(t)

	// A user needs an email; the name is made from it.
	if err := adminQuery(env.adminConfig, `mutation { addUser(name: "dana") { name } }`, nil, &struct{}{}); err == nil ||
		!strings.Contains(err.Error(), "email") {
		t.Fatalf("a user without an email: %v", err)
	}
	var added struct{ AddUser struct{ Name, Email string } }
	if err := adminQuery(env.adminConfig, `mutation { addUser(email: " Dana.Cohen@Example.com ") { name email } }`, nil, &added); err != nil {
		t.Fatal(err)
	}
	if added.AddUser.Name != "dana.cohen" || added.AddUser.Email != "dana.cohen@example.com" {
		t.Fatalf("added %+v", added.AddUser)
	}
	if err := adminQuery(env.adminConfig, `mutation { addUser(email: "dana.cohen@example.com", name: "dana2") { name } }`, nil, &struct{}{}); err == nil {
		t.Fatal("two users with one email")
	}
	if err := adminQuery(env.adminConfig, `mutation { addUser(email: "not an email") { name } }`, nil, &struct{}{}); err == nil {
		t.Fatal("a user with a bad email")
	}

	// enroll-code, by email: mailed, and nothing that enrolls comes back.
	var data struct {
		CreateEnrollmentCode struct {
			Code      *string
			EmailedTo *string
			User      string
		}
	}
	if err := adminQuery(env.adminConfig, `mutation { createEnrollmentCode(user: "DANA.cohen@example.com") { code emailedTo user } }`, nil, &data); err != nil {
		t.Fatal(err)
	}
	c := data.CreateEnrollmentCode
	if c.Code != nil || c.EmailedTo == nil || *c.EmailedTo != "dana.cohen@example.com" || c.User != "dana.cohen" {
		t.Fatalf("createEnrollmentCode answered %+v", c)
	}
	if len(f.sent) != 1 || f.sent[0].to != "dana.cohen@example.com" {
		t.Fatalf("mailed %+v", f.sent)
	}
	link := regexp.MustCompile(`ptt://enroll\?\S+`).FindString(f.sent[0].body)
	u, err := url.Parse(link)
	if err != nil || link == "" {
		t.Fatalf("no link in %q", f.sent[0].body)
	}
	q := u.Query()
	if q.Get("server") != "https://ptt.test:56400" || len(q.Get("fingerprint")) != 64 || q.Get("code") == "" ||
		!strings.Contains(f.sent[0].body, "Code     "+q.Get("code")) {
		t.Fatalf("link %s in %q", link, f.sent[0].body)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if r := env.enroll(t, q.Get("code"), key); r.Typename != "EnrolledDevice" || r.User != "dana.cohen" {
		t.Fatalf("enrolling with the mailed code: %+v", r)
	}
	if r := env.enroll(t, q.Get("code"), key); r.Typename == "EnrolledDevice" {
		t.Fatal("the mailed code worked twice")
	}
}

// TestUsersAddedByNameGetAnEmail: a user from before emails were the identity gets no link until it has one, then
// gets it at that address.
func TestUsersAddedByNameGetAnEmail(t *testing.T) {
	env, f := newMailEnv(t)
	if _, err := env.server.users.Add("hen", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := adminQuery(env.adminConfig, `mutation { createEnrollmentCode(user: "hen") { code } }`, nil, &struct{}{}); err == nil ||
		!strings.Contains(err.Error(), "user email hen") {
		t.Fatalf("a link for a user without an email: %v", err)
	}
	var set struct{ SetUserEmail struct{ Name, Email string } }
	if err := adminQuery(env.adminConfig, `mutation { setUserEmail(user: "hen", email: "Hen@Example.com") { name email } }`, nil, &set); err != nil {
		t.Fatal(err)
	}
	if set.SetUserEmail.Email != "hen@example.com" {
		t.Fatalf("set %+v", set.SetUserEmail)
	}
	if err := adminQuery(env.adminConfig, `mutation { addUser(email: "hen@example.com") { name } }`, nil, &struct{}{}); err == nil {
		t.Fatal("a second user with hen's email")
	}
	if err := adminQuery(env.adminConfig, `mutation { createEnrollmentCode(user: "hen") { code } }`, nil, &struct{}{}); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != 1 || f.sent[0].to != "hen@example.com" {
		t.Fatalf("mailed %+v", f.sent)
	}
	var users struct {
		Users []struct{ Name, Email string }
	}
	if err := adminQuery(env.adminConfig, `{ users { name email } }`, nil, &users); err != nil || len(users.Users) != 1 ||
		users.Users[0].Email != "hen@example.com" {
		t.Fatalf("users: %+v %v", users, err)
	}
}

// TestNoMailLoginNoLink: with gmail set but no mail-login yet, enroll-code says so and leaves no code waiting.
func TestNoMailLoginNoLink(t *testing.T) {
	env, _ := newMailEnv(t)
	env.server.mail = nil
	env.addUserWithEmail(t, "dana@example.com")
	if err := adminQuery(env.adminConfig, `mutation { createEnrollmentCode(user: "dana@example.com") { code } }`, nil, &struct{}{}); err == nil ||
		!strings.Contains(err.Error(), "mail-login") {
		t.Fatalf("no mail-login: %v", err)
	}
}

func (e *testEnv) addUserWithEmail(t *testing.T, email string) {
	t.Helper()
	if err := adminQuery(e.adminConfig, `mutation($e: String!) { addUser(email: $e) { name } }`, map[string]any{"e": email}, &struct{}{}); err != nil {
		t.Fatal(err)
	}
}
