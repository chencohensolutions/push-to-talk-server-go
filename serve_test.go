package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/discovery"
)

// testEnv is a real server on loopback: the public API over TLS (as phones reach it) and the admin API (as the
// commands reach it), with its own CA, users.json and devices.json in a temporary folder.
type testEnv struct {
	*server
	public *httptest.Server
	admin  *httptest.Server
	roots  *x509.CertPool
	// adminConfig points the admin commands (adminQuery) at this env's admin API.
	adminConfig auth.AppConfig
}

func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// newTestEnv starts a server with no users; configure changes the config before the server starts.
func newTestEnv(t *testing.T, configure ...func(*auth.AppConfig)) *testEnv {
	t.Helper()
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, caCert, &serverKey.PublicKey, caKey)
	serverLeaf, _ := x509.ParseCertificate(serverDER)

	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER)
	keyDER, _ := x509.MarshalECPrivateKey(caKey)
	writePEM(t, filepath.Join(dir, "ca-key.pem"), "EC PRIVATE KEY", keyDER)
	config := auth.AppConfig{
		ClientCA:     filepath.Join(dir, "ca.pem"),
		ClientCAKey:  filepath.Join(dir, "ca-key.pem"),
		PublicURL:    "https://ptt.test:56400",
		UsersFile:    filepath.Join(dir, "users.json"),
		DevicesFile:  filepath.Join(dir, "devices.json"),
		PairsFile:    filepath.Join(dir, "pairs.json"),
		GroupsFile:   filepath.Join(dir, "groups.json"),
		InvitesFile:  filepath.Join(dir, "invites.json"),
		DatabaseFile: filepath.Join(dir, "ptt.db"),
		EnrolledOnly: true,
	}.WithDefaults()
	for _, change := range configure {
		change(&config)
	}
	s, err := openServer(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.store.Close() }) // before the folder is removed: Windows can't remove an open file
	d, err := newServerDiscovery(config, serverLeaf, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	s.discovery = d.forPhones

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	public := httptest.NewUnstartedServer(s.newMux())
	public.TLS = tlsConfigFor(tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}, pool)
	public.StartTLS()
	t.Cleanup(public.Close)

	const token = "test-admin-token"
	admin := httptest.NewServer(s.newAdminMux(token))
	t.Cleanup(admin.Close)
	tokenFile := filepath.Join(dir, "admin.token")
	os.WriteFile(tokenFile, []byte(token+"\n"), 0o600)
	adminConfig := config
	adminConfig.AdminAddr = strings.TrimPrefix(admin.URL, "http://")
	adminConfig.AdminTokenFile = tokenFile
	return &testEnv{server: s, public: public, admin: admin, roots: pool, adminConfig: adminConfig}
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) client(cert *tls.Certificate) *http.Client {
	tlsConfig := &tls.Config{RootCAs: e.roots}
	if cert != nil {
		tlsConfig.Certificates = []tls.Certificate{*cert}
	}
	// Over HTTP/2, as OkHttp and URLSession connect; a custom TLS config turns it off unless asked for.
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}}
}

type gqlResponse struct {
	Status int
	Data   map[string]json.RawMessage
	Errors []struct {
		Message    string
		Extensions map[string]any
	}
}

func (e *testEnv) graphql(t *testing.T, client *http.Client, query string, variables map[string]any) gqlResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"query": query, "variables": variables})
	resp, err := client.Post(e.public.URL+"/query", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	result := gqlResponse{Status: resp.StatusCode}
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

// addUser adds a user through the admin API, as `ptt-server user add` does.
func (e *testEnv) addUser(t *testing.T, name string) {
	t.Helper()
	var data struct{ AddUser struct{ Name string } }
	if err := adminQuery(e.adminConfig, `mutation($n: String!) { addUser(name: $n) { name } }`, map[string]any{"n": name}, &data); err != nil {
		t.Fatal(err)
	}
}

// enrollmentCode makes a code through the admin API, as `ptt-server enroll-code` does.
func (e *testEnv) enrollmentCode(t *testing.T, user string) string {
	t.Helper()
	var data struct{ CreateEnrollmentCode struct{ Code, User string } }
	if err := adminQuery(e.adminConfig, `mutation($u: String!) { createEnrollmentCode(user: $u) { code user } }`,
		map[string]any{"u": user}, &data); err != nil {
		t.Fatal(err)
	}
	return data.CreateEnrollmentCode.Code
}

const enrollMutation = `mutation($input: EnrollDeviceInput!) {
	enrollDevice(input: $input) {
		__typename
		... on EnrolledDevice { user deviceName deviceNumber certificate serial expiresAt caCertificate }
		... on EnrollmentRejected { reason }
	}
}`

type enrollResult struct {
	Typename      string `json:"__typename"`
	User          string
	DeviceName    string
	DeviceNumber  int
	Certificate   string
	Serial        string
	CaCertificate string
	Reason        string
}

func csrOf(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(csr)
}

func (e *testEnv) enroll(t *testing.T, code string, key *ecdsa.PrivateKey) enrollResult {
	t.Helper()
	resp := e.graphql(t, e.client(nil), enrollMutation, map[string]any{"input": map[string]any{
		"code":          code,
		"deviceName":    "Pixel 9 Pro",
		"csr":           csrOf(t, key),
		"keyProtection": "STRONGBOX",
	}})
	if len(resp.Errors) > 0 {
		t.Fatalf("enrollDevice errors: %+v", resp.Errors)
	}
	var result enrollResult
	json.Unmarshal(resp.Data["enrollDevice"], &result)
	return result
}

// device enrolls a new phone of user with a code from the admin API, and is its client over mTLS.
func (e *testEnv) device(t *testing.T, user string) (*http.Client, enrollResult, tls.Certificate) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	result := e.enroll(t, e.enrollmentCode(t, user), key)
	if result.Typename != "EnrolledDevice" {
		t.Fatalf("enroll = %+v", result)
	}
	der, _ := base64.StdEncoding.DecodeString(result.Certificate)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return e.client(&cert), result, cert
}

// The whole of phase 1 from the server's side: a user is added and gets a code from the admin API, a phone enrolls
// with a P-256 certificate request, and then reaches me and serverInfo over mTLS with its device number.
func TestAPhoneEnrollsAndConnects(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "hen")
	code := env.enrollmentCode(t, "hen")

	preview := env.graphql(t, env.client(nil), `query($code: String!) {
		enrollmentPreview(code: $code) { __typename ... on EnrollmentPreview { user expiresAt } }
	}`, map[string]any{"code": strings.ToLower(code)})
	if !strings.Contains(string(preview.Data["enrollmentPreview"]), `"user":"hen"`) {
		t.Fatalf("preview = %s %+v", preview.Data["enrollmentPreview"], preview.Errors)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	result := env.enroll(t, code, key)
	if result.Typename != "EnrolledDevice" || result.User != "hen" || result.DeviceName != "Pixel 9 Pro" ||
		result.DeviceNumber != 1 || !strings.Contains(result.CaCertificate, "BEGIN CERTIFICATE") {
		t.Fatalf("enroll = %+v", result)
	}
	if again := env.enroll(t, code, key); again.Reason != "INVALID_CODE" {
		t.Fatalf("second use of the code = %+v", again)
	}
	der, _ := base64.StdEncoding.DecodeString(result.Certificate)
	phone := env.client(&tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})

	me := env.graphql(t, phone, `{ me { user deviceNumber deviceName } }`, nil)
	if got := string(me.Data["me"]); len(me.Errors) > 0 || got != `{"user":"hen","deviceNumber":1,"deviceName":"Pixel 9 Pro"}` {
		t.Fatalf("me = %s %+v", got, me.Errors)
	}

	info := env.graphql(t, phone, `{ serverInfo { api version deviceNumber caCertificate renewCertificates
		discovery { fingerprint id key addresses } } }`, nil)
	var got struct {
		API           int
		Version       string
		DeviceNumber  int
		CaCertificate string
		Discovery     struct {
			Fingerprint, ID, Key string
			Addresses            []string
		}
	}
	if err := json.Unmarshal(info.Data["serverInfo"], &got); err != nil || len(info.Errors) > 0 {
		t.Fatalf("serverInfo = %s %+v", info.Data["serverInfo"], info.Errors)
	}
	serverCert := env.public.Certificate()
	dhtKey, _ := discovery.KeyFor(env.public.TLS.Certificates[0].PrivateKey)
	if got.API != 1 || got.Version == "" || got.DeviceNumber != 1 || got.CaCertificate != result.CaCertificate ||
		got.Discovery.Fingerprint != discovery.Fingerprint(serverCert) ||
		got.Discovery.ID != discovery.FormatID(got.Discovery.Fingerprint) ||
		got.Discovery.Key != hex.EncodeToString(dhtKey.Public().(ed25519.PublicKey)) ||
		len(got.Discovery.Addresses) == 0 || got.Discovery.Addresses[0] != "https://ptt.test:56400" {
		t.Fatalf("serverInfo = %+v", got)
	}

	// A second phone of the same user is device 2; another user's first is device 1.
	tablet, second, _ := env.device(t, "hen")
	if second.DeviceNumber != 2 {
		t.Fatalf("second device = %+v", second)
	}
	if me := env.graphql(t, tablet, `{ me { deviceNumber } }`, nil); string(me.Data["me"]) != `{"deviceNumber":2}` {
		t.Fatalf("the tablet's me = %s", me.Data["me"])
	}
	env.addUser(t, "dana")
	if _, dana, _ := env.device(t, "dana"); dana.DeviceNumber != 1 || dana.User != "dana" {
		t.Fatalf("dana's phone = %+v", dana)
	}

	// The admin commands see them.
	var devices struct {
		Devices []adminDevice
	}
	if err := adminQuery(env.adminConfig, `query { devices(user: "hen") { `+deviceFields+` } }`, nil, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices.Devices) != 2 || devices.Devices[0].DeviceNumber != 1 || devices.Devices[1].Serial != second.Serial {
		t.Fatalf("devices = %+v", devices.Devices)
	}
}

// A revoked phone is turned away with 401 on its next connection; the user's other phones aren't.
func TestARevokedCertificateGets401(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "hen")
	phone, enrolled, cert := env.device(t, "hen")
	tablet, _, _ := env.device(t, "hen")
	if r := env.graphql(t, phone, `{ me { user } }`, nil); r.Status != http.StatusOK || len(r.Errors) > 0 {
		t.Fatalf("before revoking: %+v", r)
	}
	var data struct{ RevokeDevice adminDevice }
	if err := adminQuery(env.adminConfig, `mutation($s: String!) { revokeDevice(serial: $s) { `+deviceFields+` } }`,
		map[string]any{"s": strings.ToUpper(enrolled.Serial)}, &data); err != nil {
		t.Fatal(err)
	}
	if data.RevokeDevice.RevokedAt == nil || data.RevokeDevice.DeviceNumber != 1 {
		t.Fatalf("revoked = %+v", data.RevokeDevice)
	}
	// A new connection, so the revoked certificate is checked again.
	revoked := env.client(&cert)
	for _, query := range []string{`{ me { user } }`, `{ serverInfo { version } }`} {
		if r := env.graphql(t, revoked, query, nil); r.Status != http.StatusUnauthorized {
			t.Errorf("%s with a revoked certificate: %d", query, r.Status)
		}
	}
	if r := env.graphql(t, tablet, `{ me { deviceNumber } }`, nil); r.Status != http.StatusOK || string(r.Data["me"]) != `{"deviceNumber":2}` {
		t.Fatalf("the other phone: %d %s", r.Status, r.Data["me"])
	}
}

// A removed user's phones are refused, its pending codes enroll nothing, and the same name added again starts with
// none of its devices.
func TestARemovedUserIsLockedOut(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "hen")
	_, _, cert := env.device(t, "hen")
	pending := env.enrollmentCode(t, "hen")
	var removed struct{ RemoveUser struct{ RevokedDevices int } }
	if err := adminQuery(env.adminConfig, `mutation { removeUser(name: "hen") { revokedDevices } }`, nil, &removed); err != nil {
		t.Fatal(err)
	}
	if removed.RemoveUser.RevokedDevices != 1 {
		t.Fatalf("removeUser = %+v", removed)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if r := env.enroll(t, pending, key); r.Reason != "INVALID_CODE" {
		t.Fatalf("a removed user's code: %+v", r)
	}
	if r := env.graphql(t, env.client(&cert), `{ me { user } }`, nil); r.Status != http.StatusUnauthorized {
		t.Fatalf("a removed user's phone: %d", r.Status)
	}
	env.addUser(t, "hen")
	if r := env.graphql(t, env.client(&cert), `{ me { user } }`, nil); r.Status != http.StatusUnauthorized {
		t.Fatalf("the phone after hen was added again: %d", r.Status)
	}
	if _, again, _ := env.device(t, "hen"); again.DeviceNumber != 2 {
		t.Fatalf("a new phone of the new hen: %+v", again)
	}
	var data struct{ CreateEnrollmentCode struct{ Code string } }
	if err := adminQuery(env.adminConfig, `mutation { createEnrollmentCode(user: "nobody") { code } }`, nil, &data); err == nil ||
		!strings.Contains(err.Error(), "unknown user") {
		t.Fatalf("a code for an unknown user: %v", err)
	}
}

func TestAnonymousClientsReachOnlyPublicFields(t *testing.T) {
	env := newTestEnv(t)
	anonymous := env.client(nil)
	for _, query := range []string{
		`{ serverInfo { version } }`,
		`{ me { user } }`,
		`mutation { renewCertificate(csr: "x", keyProtection: TEE) { __typename } }`,
		`{ __schema { queryType { name } } }`,
		`{ __type(name: "Me") { name } }`,
	} {
		resp := env.graphql(t, anonymous, query, nil)
		if len(resp.Errors) == 0 || !strings.Contains(resp.Errors[0].Message, "client certificate required") ||
			resp.Errors[0].Extensions["code"] != "UNAUTHORIZED" {
			t.Errorf("%s: errors = %+v", query, resp.Errors)
		}
	}
	resp := env.graphql(t, anonymous, `{ enrollmentPreview(code: "AAAA-AAAA") { ... on EnrollmentRejected { reason } } }`, nil)
	if len(resp.Errors) > 0 || !strings.Contains(string(resp.Data["enrollmentPreview"]), "INVALID_CODE") {
		t.Fatalf("preview: %+v %s", resp.Errors, resp.Data["enrollmentPreview"])
	}
	// More than an enrollment needs, without a certificate.
	big := `{"query": "{ enrollmentPreview(code: \"` + strings.Repeat("A", 70<<10) + `\") { __typename } }"}`
	r, err := anonymous.Post(env.public.URL+"/query", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 70 KB anonymous request: %d", r.StatusCode)
	}
}

// Wrong codes from one address are limited across enrollmentPreview and enrollDevice.
func TestWrongCodesAreRateLimited(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "hen")
	anonymous := env.client(nil)
	for range 5 {
		env.graphql(t, anonymous, `{ enrollmentPreview(code: "AAAA-AAAA") { __typename } }`, nil)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if r := env.enroll(t, env.enrollmentCode(t, "hen"), key); r.Reason != "RATE_LIMITED" {
		t.Fatalf("after 5 wrong codes: %+v", r)
	}
}

func TestAdminAPIRequiresToken(t *testing.T) {
	env := newTestEnv(t)
	for _, auth := range []string{"", "Bearer wrong", "test-admin-token"} {
		req, _ := http.NewRequest(http.MethodPost, env.admin.URL+"/admin/query", strings.NewReader(`{"query":"{ users { name } }"}`))
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Authorization %q: %d", auth, resp.StatusCode)
		}
	}
	// Admin operations aren't on the public API.
	env.addUser(t, "hen")
	phone, _, _ := env.device(t, "hen")
	if r := env.graphql(t, phone, `mutation { addUser(name: "eve") { name } }`, nil); r.Status == http.StatusOK && len(r.Errors) == 0 {
		t.Fatalf("addUser on /query: %+v", r)
	}
}

func TestAdminListenerMustBeLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8082": true,
		"localhost:8082": true,
		"[::1]:8082":     true,
		"0.0.0.0:8082":   false,
		":8082":          false,
		"192.168.1.2:82": false,
	} {
		if err := requireLoopback(addr); (err == nil) != ok {
			t.Errorf("requireLoopback(%q) = %v", addr, err)
		}
	}
}

// With "enrolled_only", a certificate the CA signed but the registry doesn't list is refused.
func TestOnlyEnrolledCertificatesWhenSet(t *testing.T) {
	for _, only := range []bool{false, true} {
		env := newTestEnv(t, func(c *auth.AppConfig) { c.EnrolledOnly = only })
		env.addUser(t, "hen")
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		csr, _ := x509.ParseCertificateRequest(der)
		cert, err := env.enrollment.Issuer.Issue(csr, "hen")
		if err != nil {
			t.Fatal(err)
		}
		unlisted := env.client(&tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key})
		resp := env.graphql(t, unlisted, `{ serverInfo { deviceNumber } }`, nil)
		if want := map[bool]int{false: 200, true: 401}[only]; resp.Status != want {
			t.Errorf("enrolled_only %v: a certificate the registry doesn't list got %d, want %d", only, resp.Status, want)
		}
		if !only && string(resp.Data["serverInfo"]) != `{"deviceNumber":0}` {
			t.Errorf("an unlisted certificate's device number: %s", resp.Data["serverInfo"])
		}
	}
}

// A certificate for a CN that isn't a user (made with the CA, never enrolled) is refused.
func TestACertificateForNoUserIsRefused(t *testing.T) {
	env := newTestEnv(t, func(c *auth.AppConfig) { c.EnrolledOnly = false })
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csr, _ := x509.ParseCertificateRequest(der)
	cert, _ := env.enrollment.Issuer.Issue(csr, "nobody")
	if r := env.graphql(t, env.client(&tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}), `{ me { user } }`, nil); r.Status != 401 {
		t.Fatalf("a certificate for no user: %d", r.Status)
	}
}
