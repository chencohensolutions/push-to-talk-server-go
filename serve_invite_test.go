package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
)

// sentMail keeps what the server would have emailed.
type sentMail struct {
	mu   sync.Mutex
	mail []struct{ to, subject, body string }
}

func (m *sentMail) Send(to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mail = append(m.mail, struct{ to, subject, body string }{to, subject, body})
	return nil
}

var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// lastCode is the six-digit code of the last email to to.
func (m *sentMail) lastCode(t *testing.T, to string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.mail) - 1; i >= 0; i-- {
		if m.mail[i].to == to {
			return sixDigits.FindString(m.mail[i].body)
		}
	}
	t.Fatalf("no email to %s", to)
	return ""
}

func (e *testEnv) mailbox() *sentMail {
	m := &sentMail{}
	e.invites.Mail = m
	return m
}

func (e *testEnv) createInvite(t *testing.T, p *phone, email string) (string, string) {
	t.Helper()
	vars := map[string]any{}
	if email != "" {
		vars["email"] = email
	}
	r := e.graphql(t, p.client, `mutation($email: String) { createInvite(email: $email) { code invite { id email expiresAt } } }`, vars)
	if code := errorCode(r); code != "" {
		return "", code
	}
	var got struct{ Code string }
	json.Unmarshal(r.Data["createInvite"], &got)
	if len(r.Errors) > 0 || len(got.Code) != 22 {
		t.Fatalf("createInvite: %s %+v", r.Data["createInvite"], r.Errors)
	}
	return got.Code, ""
}

// anonymous runs a public field without a certificate and gives its answer.
func (e *testEnv) anonymous(t *testing.T, query string, vars map[string]any, field string) string {
	t.Helper()
	r := e.graphql(t, e.client(nil), query, vars)
	if len(r.Errors) > 0 {
		t.Fatalf("%s: %+v", field, r.Errors)
	}
	return string(r.Data[field])
}

const emailCodeMutation = `mutation($code: String!, $email: String!) {
	inviteEmailCode(code: $code, email: $email) { __typename ... on InviteEmailSent { email } ... on InviteRejected { reason } }
}`

const enrollWithInviteMutation = `mutation($input: InviteEnrollInput!) {
	enrollWithInvite(input: $input) {
		__typename
		... on InviteEnrolled { device { user deviceNumber certificate serial } pairing { inviter pairingToken { token } } }
		... on InviteRejected { reason }
	}
}`

type invitedResult struct {
	Typename string `json:"__typename"`
	Reason   string
	Device   struct {
		User         string
		DeviceNumber int
		Certificate  string
		Serial       string
	}
	Pairing struct {
		Inviter      string
		PairingToken *struct{ Token string }
	}
}

func (e *testEnv) enrollWithInvite(t *testing.T, code, email, emailCode string, key *ecdsa.PrivateKey) invitedResult {
	t.Helper()
	answer := e.anonymous(t, enrollWithInviteMutation, map[string]any{"input": map[string]any{
		"code": code, "email": email, "emailCode": emailCode, "displayName": "  Dana Cohen‮ ",
		"deviceName": "Galaxy S25", "csr": csrOf(t, key), "keyProtection": "STRONGBOX",
	}}, "enrollWithInvite")
	var got invitedResult
	json.Unmarshal([]byte(answer), &got)
	return got
}

// An invite from hen to dana's email: dana's phone proves the address with the code sent there, is made a user and
// enrolled in one step, and pairs with hen using the pairing token the invite gives, as after scanning hen's QR code.
func TestAFriendJoinsByAnInvite(t *testing.T) {
	env := newTestEnv(t)
	box := env.mailbox()
	env.addUser(t, "hen")
	hen := env.phone(t, "hen")
	env.uploadKeys(t, hen, ecKey())

	if _, problem := env.createInvite(t, hen, "not an email"); problem != "INVALID_EMAIL" {
		t.Fatalf("an invite for a bad address: %s", problem)
	}
	code, _ := env.createInvite(t, hen, " Dana@Example.com ")
	preview := env.anonymous(t, `query($c: String!) { invitePreview(code: $c) { __typename ... on InvitePreview { inviter email } } }`,
		map[string]any{"c": code}, "invitePreview")
	if preview != `{"__typename":"InvitePreview","inviter":"hen","email":"dana@example.com"}` {
		t.Fatalf("preview = %s", preview)
	}
	if got := env.anonymous(t, emailCodeMutation, map[string]any{"code": code, "email": "eve@example.com"}, "inviteEmailCode"); !strings.Contains(got, "EMAIL_MISMATCH") {
		t.Fatalf("a code to another address: %s", got)
	}
	if got := env.anonymous(t, emailCodeMutation, map[string]any{"code": "wrong", "email": "dana@example.com"}, "inviteEmailCode"); !strings.Contains(got, "INVALID_CODE") {
		t.Fatalf("a wrong invite: %s", got)
	}
	if got := env.anonymous(t, emailCodeMutation, map[string]any{"code": code, "email": "DANA@example.com"}, "inviteEmailCode"); got != `{"__typename":"InviteEmailSent","email":"dana@example.com"}` {
		t.Fatalf("the email code: %s", got)
	}
	if got := env.anonymous(t, emailCodeMutation, map[string]any{"code": code, "email": "dana@example.com"}, "inviteEmailCode"); !strings.Contains(got, "RATE_LIMITED") {
		t.Fatalf("a second code at once: %s", got)
	}
	digits := box.lastCode(t, "dana@example.com")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrong := "000000"
	if digits == wrong {
		wrong = "111111"
	}
	if got := env.enrollWithInvite(t, code, "dana@example.com", wrong, key); got.Reason != "WRONG_EMAIL_CODE" {
		t.Fatalf("a wrong email code: %+v", got)
	}
	got := env.enrollWithInvite(t, code, "dana@example.com", digits[:3]+" "+digits[3:], key)
	if got.Typename != "InviteEnrolled" || got.Device.User != "dana" || got.Device.DeviceNumber != 1 ||
		got.Pairing.Inviter != "hen" || got.Pairing.PairingToken == nil || len(got.Pairing.PairingToken.Token) != 22 {
		t.Fatalf("enrollWithInvite = %+v", got)
	}
	if again := env.enrollWithInvite(t, code, "dana@example.com", digits, key); again.Reason != "INVALID_CODE" {
		t.Fatalf("the invite a second time: %+v", again)
	}
	user := env.users.Find("dana")
	if user == nil || user.Email != "dana@example.com" || user.DisplayName != "Dana Cohen" || user.InvitedBy != "hen" {
		t.Fatalf("users.json has %+v", user)
	}

	// dana's phone: its certificate works, and it pairs with hen by the token.
	der, _ := base64.StdEncoding.DecodeString(got.Device.Certificate)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	dana := &phone{user: "dana", number: 1, serial: got.Device.Serial, client: env.client(&cert), cert: cert}
	me := env.graphql(t, dana.client, `{ me { user displayName email } }`, nil)
	if string(me.Data["me"]) != `{"user":"dana","displayName":"Dana Cohen","email":"dana@example.com"}` {
		t.Fatalf("me = %s %+v", me.Data["me"], me.Errors)
	}
	env.uploadKeys(t, dana, ecKey())
	token := got.Pairing.PairingToken.Token
	if _, problem := env.bundles(t, dana, "hen", token); problem != "" {
		t.Fatalf("bundles with the invite's token: %s", problem)
	}
	henSocket, danaSocket := env.socket(t, hen), env.socket(t, dana)
	if r := danaSocket.send(t, pb.Envelope_PREKEY_MESSAGE, token, dev(hen)); r.Status != pb.SendResult_ACCEPTED {
		t.Fatalf("the pair request: %v", r)
	}
	henSocket.ack(t, henSocket.envelope(t).Id)
	if state, code := env.mutate(t, dana, "confirmPair", "hen"); state != "WAITING" {
		t.Fatalf("dana confirms: %s %s", state, code)
	}
	if state, code := env.mutate(t, hen, "confirmPair", "dana"); state != "PAIRED" {
		t.Fatalf("hen confirms: %s %s", state, code)
	}
	contacts := env.graphql(t, hen.client, `{ contacts { user displayName } }`, nil)
	if string(contacts.Data["contacts"]) != `[{"user":"dana","displayName":"Dana Cohen"}]` {
		t.Fatalf("hen's contacts: %s", contacts.Data["contacts"])
	}

	// The email is dana's now: another invite can't make a second user with it.
	again, _ := env.createInvite(t, hen, "")
	if got := env.anonymous(t, emailCodeMutation, map[string]any{"code": again, "email": "dana@EXAMPLE.com"}, "inviteEmailCode"); !strings.Contains(got, "EMAIL_TAKEN") {
		t.Fatalf("a code for a taken email: %s", got)
	}
}

const acceptMutation = `mutation($c: String!) {
	acceptInvite(code: $c) { __typename ... on InvitePairing { inviter pairingToken { token } } ... on InviteRejected { reason } }
}`

// A friend already enrolled here opens the link: the invite only gives them a pairing token of the inviter.
func TestAnEnrolledFriendAcceptsAnInvite(t *testing.T) {
	env := newTestEnv(t)
	env.mailbox()
	env.addUsers(t, "hen", "dana")
	hen, dana := env.phone(t, "hen"), env.phone(t, "dana")
	code, _ := env.createInvite(t, hen, "")

	own := env.graphql(t, hen.client, acceptMutation, map[string]any{"c": code})
	if !strings.Contains(string(own.Data["acceptInvite"]), "OWN_INVITE") {
		t.Fatalf("hen's own invite: %s %+v", own.Data["acceptInvite"], own.Errors)
	}
	r := env.graphql(t, dana.client, acceptMutation, map[string]any{"c": code})
	var got struct {
		Typename     string `json:"__typename"`
		Inviter      string
		PairingToken struct{ Token string }
	}
	json.Unmarshal(r.Data["acceptInvite"], &got)
	if got.Typename != "InvitePairing" || got.Inviter != "hen" || len(got.PairingToken.Token) != 22 {
		t.Fatalf("acceptInvite = %s %+v", r.Data["acceptInvite"], r.Errors)
	}
	if again := env.graphql(t, dana.client, acceptMutation, map[string]any{"c": code}); !strings.Contains(string(again.Data["acceptInvite"]), "INVALID_CODE") {
		t.Fatalf("a used invite: %s", again.Data["acceptInvite"])
	}
	// Anonymous phones can't redeem it this way.
	if anon := env.graphql(t, env.client(nil), acceptMutation, map[string]any{"c": code}); errorCode(anon) != "UNAUTHORIZED" {
		t.Fatalf("acceptInvite without a certificate: %+v", anon.Errors)
	}
}

// Invites have limits: five waiting per user, cancel, and none at all when the config turns them off.
func TestInviteLimits(t *testing.T) {
	env := newTestEnv(t)
	env.mailbox()
	env.addUser(t, "hen")
	hen := env.phone(t, "hen")
	for i := range 5 {
		if _, problem := env.createInvite(t, hen, ""); problem != "" {
			t.Fatal(i, problem)
		}
	}
	if _, problem := env.createInvite(t, hen, ""); problem != "RATE_LIMITED" {
		t.Fatalf("a sixth invite: %s", problem)
	}
	list := env.graphql(t, hen.client, `{ invites { id } }`, nil)
	var invites []struct{ ID string }
	json.Unmarshal(list.Data["invites"], &invites)
	if len(invites) != 5 {
		t.Fatalf("invites = %s", list.Data["invites"])
	}
	cancel := env.graphql(t, hen.client, `mutation($id: String!) { cancelInvite(id: $id) }`, map[string]any{"id": invites[0].ID})
	if string(cancel.Data["cancelInvite"]) != "true" {
		t.Fatalf("cancelInvite = %s %+v", cancel.Data["cancelInvite"], cancel.Errors)
	}
	if _, problem := env.createInvite(t, hen, ""); problem != "" {
		t.Fatalf("an invite after canceling one: %s", problem)
	}

	off := newTestEnv(t, func(c *auth.AppConfig) { no := false; c.Invites = &no })
	off.addUser(t, "hen")
	if _, problem := off.createInvite(t, off.phone(t, "hen"), ""); problem != "INVITES_OFF" {
		t.Fatalf("an invite with invites off: %s", problem)
	}
}
