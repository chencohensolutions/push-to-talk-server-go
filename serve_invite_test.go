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
	"testing"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	pb "github.com/chencohensolutions/push-to-talk-server-go/proto/pttv1"
)

var sixDigits = regexp.MustCompile(`^\d{6}$`)

func (e *testEnv) createInvite(t *testing.T, p *phone, email string) (string, string) {
	t.Helper()
	code, _, problem := e.createInviteWithPasscode(t, p, email)
	return code, problem
}

// createInviteWithPasscode is createInvite with the passcode the inviter's phone sends beside the link.
func (e *testEnv) createInviteWithPasscode(t *testing.T, p *phone, email string) (string, string, string) {
	t.Helper()
	vars := map[string]any{}
	if email != "" {
		vars["email"] = email
	}
	r := e.graphql(t, p.client, `mutation($email: String) { createInvite(email: $email) { code passcode invite { id email expiresAt } } }`, vars)
	if code := errorCode(r); code != "" {
		return "", "", code
	}
	var got struct {
		Code     string
		Passcode string
	}
	json.Unmarshal(r.Data["createInvite"], &got)
	if len(r.Errors) > 0 || len(got.Code) != 22 || !sixDigits.MatchString(got.Passcode) {
		t.Fatalf("createInvite: %s %+v", r.Data["createInvite"], r.Errors)
	}
	return got.Code, got.Passcode, ""
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

// redeem is what a friend's phone sends with enrollWithInvite; an empty email is sent as null.
type redeem struct {
	code, passcode, email, name string
}

func (e *testEnv) enrollWithInvite(t *testing.T, r redeem, key *ecdsa.PrivateKey) invitedResult {
	t.Helper()
	if r.name == "" {
		r.name = "  Dana Cohen‮ "
	}
	input := map[string]any{
		"code": r.code, "passcode": r.passcode, "displayName": r.name,
		"deviceName": "Galaxy S25", "csr": csrOf(t, key), "keyProtection": "STRONGBOX",
	}
	if r.email != "" {
		input["email"] = r.email
	}
	answer := e.anonymous(t, enrollWithInviteMutation, map[string]any{"input": input}, "enrollWithInvite")
	var got invitedResult
	json.Unmarshal([]byte(answer), &got)
	return got
}

// otherDigits is six digits that aren't passcode.
func otherDigits(passcode string) string {
	if passcode == "000000" {
		return "111111"
	}
	return "000000"
}

// An invite from hen to dana's email: hen's phone sends the link and its passcode (the server sends nothing), and
// dana's phone, with both and that email, is made a user and enrolled in one step, then pairs with hen using the
// pairing token the invite gives, as after scanning hen's QR code.
func TestAFriendJoinsByAnInvite(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "hen")
	hen := env.phone(t, "hen")
	env.uploadKeys(t, hen, ecKey())

	if _, problem := env.createInvite(t, hen, "not an email"); problem != "INVALID_EMAIL" {
		t.Fatalf("an invite for a bad address: %s", problem)
	}
	code, passcode, _ := env.createInviteWithPasscode(t, hen, " Dana@Example.com ")
	preview := env.anonymous(t, `query($c: String!) { invitePreview(code: $c) { __typename ... on InvitePreview { inviter email } } }`,
		map[string]any{"c": code}, "invitePreview")
	if preview != `{"__typename":"InvitePreview","inviter":"hen","email":"dana@example.com"}` {
		t.Fatalf("preview = %s", preview)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if got := env.enrollWithInvite(t, redeem{code: "wrong", passcode: passcode, email: "dana@example.com"}, key); got.Reason != "INVALID_CODE" {
		t.Fatalf("a wrong invite: %+v", got)
	}
	if got := env.enrollWithInvite(t, redeem{code: code, passcode: otherDigits(passcode), email: "dana@example.com"}, key); got.Reason != "WRONG_PASSCODE" {
		t.Fatalf("a wrong passcode: %+v", got)
	}
	// The email is checked after the passcode, so the link alone doesn't tell whether an address is taken.
	if got := env.enrollWithInvite(t, redeem{code: code, passcode: passcode, email: "eve@example.com"}, key); got.Reason != "EMAIL_MISMATCH" {
		t.Fatalf("enrolling with another email: %+v", got)
	}
	if got := env.enrollWithInvite(t, redeem{code: code, passcode: passcode}, key); got.Reason != "EMAIL_MISMATCH" {
		t.Fatalf("enrolling without the invite's email: %+v", got)
	}
	got := env.enrollWithInvite(t, redeem{code: code, passcode: passcode[:3] + " " + passcode[3:], email: "DANA@example.com"}, key)
	if got.Typename != "InviteEnrolled" || got.Device.User != "dana" || got.Device.DeviceNumber != 1 ||
		got.Pairing.Inviter != "hen" || got.Pairing.PairingToken == nil || len(got.Pairing.PairingToken.Token) != 22 {
		t.Fatalf("enrollWithInvite = %+v", got)
	}
	if again := env.enrollWithInvite(t, redeem{code: code, passcode: passcode, email: "dana@example.com"}, key); again.Reason != "INVALID_CODE" {
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
	again, passcode, _ := env.createInviteWithPasscode(t, hen, "")
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if got := env.enrollWithInvite(t, redeem{code: again, passcode: passcode, email: "dana@EXAMPLE.com"}, other); got.Reason != "EMAIL_TAKEN" {
		t.Fatalf("a taken email: %+v", got)
	}
}

// An invite without an email: it has a passcode all the same, and the friend may give their own email (not
// verified) or none; without one, their user name is made from their display name.
func TestAnInviteForAnyone(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "hen")
	hen := env.phone(t, "hen")
	code, passcode, _ := env.createInviteWithPasscode(t, hen, "")
	preview := env.anonymous(t, `query($c: String!) { invitePreview(code: $c) { ... on InvitePreview { inviter email } } }`,
		map[string]any{"c": code}, "invitePreview")
	if preview != `{"inviter":"hen","email":null}` {
		t.Fatalf("preview = %s", preview)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if got := env.enrollWithInvite(t, redeem{code: code, passcode: ""}, key); got.Reason != "WRONG_PASSCODE" {
		t.Fatalf("no passcode: %+v", got)
	}
	if got := env.enrollWithInvite(t, redeem{code: code, passcode: passcode, email: "not an email"}, key); got.Reason != "INVALID_EMAIL" {
		t.Fatalf("a bad email: %+v", got)
	}
	got := env.enrollWithInvite(t, redeem{code: code, passcode: passcode, email: " Eve@Example.com", name: "Eve Levi"}, key)
	if got.Typename != "InviteEnrolled" || got.Device.User != "eve" || got.Pairing.Inviter != "hen" {
		t.Fatalf("enrollWithInvite = %+v", got)
	}
	if eve := env.users.Find("eve"); eve == nil || eve.Email != "eve@example.com" || eve.DisplayName != "Eve Levi" {
		t.Fatalf("users.json has %+v", eve)
	}
	if again := env.enrollWithInvite(t, redeem{code: code, passcode: passcode, name: "Eve Levi"}, key); again.Reason != "INVALID_CODE" {
		t.Fatalf("the invite a second time: %+v", again)
	}

	code, passcode, _ = env.createInviteWithPasscode(t, hen, "")
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	got = env.enrollWithInvite(t, redeem{code: code, passcode: passcode, name: "Avi Mizrahi"}, other)
	if got.Typename != "InviteEnrolled" || got.Device.User != "avi.mizrahi" {
		t.Fatalf("enrollWithInvite without an email = %+v", got)
	}
	if avi := env.users.Find("avi.mizrahi"); avi == nil || avi.Email != "" || avi.InvitedBy != "hen" {
		t.Fatalf("users.json has %+v", avi)
	}
}

// Wrong passcodes count against the client's address, as wrong enrollment codes do: five in a minute, then even
// the right one waits.
func TestWrongPasscodesAreLimited(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "hen")
	hen := env.phone(t, "hen")
	code, passcode, _ := env.createInviteWithPasscode(t, hen, "")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for i := range 5 {
		if got := env.enrollWithInvite(t, redeem{code: code, passcode: otherDigits(passcode)}, key); got.Reason != "WRONG_PASSCODE" {
			t.Fatalf("wrong passcode %d: %+v", i, got)
		}
	}
	if got := env.enrollWithInvite(t, redeem{code: code, passcode: passcode}, key); got.Reason != "RATE_LIMITED" {
		t.Fatalf("the right passcode after five wrong ones: %+v", got)
	}
}

const acceptMutation = `mutation($c: String!) {
	acceptInvite(code: $c) { __typename ... on InvitePairing { inviter pairingToken { token } } ... on InviteRejected { reason } }
}`

// A friend already enrolled here opens the link: the invite only gives them a pairing token of the inviter.
func TestAnEnrolledFriendAcceptsAnInvite(t *testing.T) {
	env := newTestEnv(t)
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
