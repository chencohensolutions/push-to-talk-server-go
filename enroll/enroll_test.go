package enroll

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newClock() *clock { return &clock{t: time.Date(2026, 10, 17, 14, 22, 0, 0, time.UTC)} }

func testCA(t *testing.T, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func csrFor(t *testing.T, key any, commonName string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func newTestService(t *testing.T, c *clock) *Service {
	t.Helper()
	caCert, caKey := testCA(t, c.t)
	registry, err := OpenRegistry(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	return NewService(NewIssuer(caCert, caKey, c.now), registry, c.now)
}

func TestCodeFormatAndNormalization(t *testing.T) {
	c := newClock()
	store := NewCodeStore(c.now)
	code, expiresAt := store.Create("hen")

	if len(code) != 9 || code[4] != '-' || strings.Trim(strings.Replace(code, "-", "", 1), codeAlphabet) != "" {
		t.Fatalf("unexpected code format %q", code)
	}
	if !expiresAt.Equal(c.t.Add(CodeTTL)) {
		t.Fatalf("expiresAt = %v", expiresAt)
	}

	typed := strings.ToLower(strings.Replace(code, "-", " ", 1))
	typed = strings.NewReplacer("0", "o", "1", "l").Replace(typed)
	if pending, ok := store.Peek(typed); !ok || pending.User != "hen" {
		t.Fatalf("Peek(%q) = %v, %v", typed, pending, ok)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	store := NewCodeStore(newClock().now)
	code, _ := store.Create("hen")
	if _, ok := store.Peek(code); !ok {
		t.Fatal("Peek should not use up the code")
	}
	if _, ok := store.Redeem(code); !ok {
		t.Fatal("first Redeem failed")
	}
	if _, ok := store.Redeem(code); ok {
		t.Fatal("second Redeem succeeded")
	}
}

func TestCodeExpires(t *testing.T) {
	c := newClock()
	store := NewCodeStore(c.now)
	code, _ := store.Create("hen")
	c.t = c.t.Add(CodeTTL)
	if _, ok := store.Redeem(code); ok {
		t.Fatal("expired code was accepted")
	}
}

func TestMalformedCodesAreRejected(t *testing.T) {
	store := NewCodeStore(newClock().now)
	for _, code := range []string{"", "K7QM-4XP", "K7QM-4XPDD", "K7QM-4XP!", "K7QM-4XPU"} {
		if _, ok := store.Peek(code); ok {
			t.Errorf("Peek(%q) succeeded", code)
		}
	}
}

func TestEnrollIssuesClientCertificateForCodeUser(t *testing.T) {
	c := newClock()
	svc := newTestService(t, c)
	code, _ := svc.Codes.Create("hen")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	enrolled, rejection, err := svc.Enroll("10.0.0.5", Request{
		Code:          code,
		DeviceName:    "  Pixel 9 Pro\n",
		CSR:           csrFor(t, key, "someone-else"),
		KeyProtection: "STRONGBOX",
	})
	if err != nil || rejection != "" {
		t.Fatalf("Enroll = %v, %v", rejection, err)
	}

	cert, err := x509.ParseCertificate(enrolled.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "hen" {
		t.Errorf("CN = %q, want the code's user, not the CSR subject", cert.Subject.CommonName)
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("certificate is not for the requested key")
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v", cert.ExtKeyUsage)
	}
	if want := c.t.Add(CertificateValidity); !cert.NotAfter.Equal(want) {
		t.Errorf("NotAfter = %v, want %v", cert.NotAfter, want)
	}

	devices := svc.Registry.List("hen")
	if len(devices) != 1 || devices[0].Name != "Pixel 9 Pro" || devices[0].Serial != SerialString(cert.SerialNumber) || devices[0].KeyProtection != "STRONGBOX" {
		t.Fatalf("registry = %+v", devices)
	}

	if _, rejection, _ := svc.Enroll("10.0.0.5", Request{Code: code, CSR: csrFor(t, key, "x")}); rejection != RejectInvalidCode {
		t.Fatalf("reusing the code: rejection = %q", rejection)
	}
}

func TestInvalidCSRDoesNotUseUpCode(t *testing.T) {
	svc := newTestService(t, newClock())
	code, _ := svc.Codes.Create("hen")
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tampered := csrFor(t, p256, "x")
	tampered[len(tampered)-1] ^= 1

	for name, csr := range map[string][]byte{
		"garbage":  []byte("not a csr"),
		"rsa":      csrFor(t, rsaKey, "x"),
		"p384":     csrFor(t, p384, "x"),
		"tampered": tampered,
	} {
		if _, rejection, _ := svc.Enroll("ip", Request{Code: code, CSR: csr}); rejection != RejectInvalidCSR {
			t.Errorf("%s: rejection = %q", name, rejection)
		}
	}
	if _, ok := svc.Codes.Peek(code); !ok {
		t.Fatal("code was used up by an invalid request")
	}
}

func TestWrongCodesAreRateLimitedPerIP(t *testing.T) {
	c := newClock()
	svc := newTestService(t, c)
	code, _ := svc.Codes.Create("hen")

	for i := range maxFailures {
		if _, rejection := svc.Preview("1.2.3.4", "AAAA-AAAA"); rejection != RejectInvalidCode {
			t.Fatalf("attempt %d: %q", i, rejection)
		}
	}
	if _, rejection := svc.Preview("1.2.3.4", code); rejection != RejectRateLimited {
		t.Fatalf("after %d failures: %q", maxFailures, rejection)
	}
	if _, rejection := svc.Preview("5.6.7.8", code); rejection != "" {
		t.Fatalf("other IP: %q", rejection)
	}

	c.t = c.t.Add(failureWindow + time.Second)
	if preview, rejection := svc.Preview("1.2.3.4", code); rejection != "" || preview.User != "hen" {
		t.Fatalf("after the window: %v, %q", preview, rejection)
	}
}

func TestRegistryPersistsAndRevokes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	registry, _ := OpenRegistry(path)
	now := newClock().t
	if _, err := registry.Add(Device{Serial: "abc", User: "hen", Name: "Pixel", RegisteredAt: now}); err != nil {
		t.Fatal(err)
	}
	if registry.IsRevoked("abc") {
		t.Fatal("new device is revoked")
	}
	if _, err := registry.Revoke("abc", now); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Revoke("missing", now); err != ErrDeviceNotFound {
		t.Fatalf("Revoke(missing) = %v", err)
	}

	reopened, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reopened.IsRevoked("abc") || len(reopened.List("")) != 1 {
		t.Fatalf("reopened registry = %+v", reopened.List(""))
	}
	if reopened.IsRevoked("unknown") {
		t.Fatal("certificates outside the registry must not count as revoked")
	}
}

func TestCleanDeviceName(t *testing.T) {
	if got := cleanDeviceName(" \t "); got != "Unnamed device" {
		t.Errorf("blank = %q", got)
	}
	long := strings.Repeat("é", 100)
	if got := cleanDeviceName(long); got != strings.Repeat("é", maxDeviceNameLength) {
		t.Errorf("long name = %q", got)
	}
}

// A revoked certificate stays revoked when the registry is lost or put back from an older copy: the revoked serials
// are kept a second time, beside it.
func TestRevokedSerialsOutliveTheRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, serial := range []string{"aa", "bb"} {
		if _, err := registry.Add(Device{Serial: serial, User: "hen", Name: serial}); err != nil {
			t.Fatal(err)
		}
	}
	old, _ := os.ReadFile(path) // a copy from before the revocation
	if _, err := registry.RevokeDevice("aa", time.Now()); err != nil {
		t.Fatal(err)
	}
	if RevokedPath(path) != filepath.Join(filepath.Dir(path), "devices.revoked.json") {
		t.Fatalf("RevokedPath = %s", RevokedPath(path))
	}
	check := func(when string) {
		t.Helper()
		opened, err := OpenRegistry(path)
		if err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		if !opened.IsRevoked("aa") || opened.IsRevoked("bb") {
			t.Errorf("%s: aa revoked %v, bb revoked %v", when, opened.IsRevoked("aa"), opened.IsRevoked("bb"))
		}
	}
	check("opened again")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	check("the registry put back from an older copy")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	check("the registry lost")
	// A registry from before the second file: its revoked devices are taken into it at the first open.
	os.Remove(RevokedPath(path))
	revokedAt := time.Now()
	data, _ := json.Marshal([]Device{{Serial: "aa", User: "hen", DeviceNumber: 1, RevokedAt: &revokedAt}, {Serial: "bb", User: "hen", DeviceNumber: 2}})
	os.WriteFile(path, data, 0o600)
	check("a registry from before the revoked file")
	os.Remove(path)
	check("and then lost")
	// A revoked file that can't be read stops the server from opening the registry.
	os.WriteFile(RevokedPath(path), []byte("{"), 0o600)
	if _, err := OpenRegistry(path); err == nil {
		t.Error("a damaged revoked file was passed over")
	}
}

// A certificate is renewed only near its end, and only a few times: a stolen one can't be kept alive by renewing it.
func TestRenewalsComeOnlyNearTheEndAndAFewTimes(t *testing.T) {
	c := newClock()
	s := newTestService(t, c)
	code, _ := s.Codes.Create("hen")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enrolled, rejection, err := s.Enroll("10.0.0.2", Request{Code: code, DeviceName: "Pixel", CSR: csrFor(t, key, "x")})
	if err != nil || rejection != "" {
		t.Fatalf("enroll: %v %v", rejection, err)
	}
	serial := enrolled.Device.Serial
	renew := func() Rejection {
		t.Helper()
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, rejection, err := s.Renew(serial, csrFor(t, k, "device"), "TEE")
		if err != nil {
			t.Fatal(err)
		}
		return rejection
	}
	if r := renew(); r != RejectRateLimited {
		t.Fatalf("a renewal a year early: %q", r)
	}
	c.t = enrolled.Device.ExpiresAt.Add(-RenewBefore)
	for i := range maxRenewals {
		if r := renew(); r != "" {
			t.Fatalf("renewal %d in the last 30 days: %q", i+1, r)
		}
	}
	if r := renew(); r != RejectRateLimited {
		t.Fatalf("renewal %d: %q", maxRenewals+1, r)
	}
}

func TestWrongCodesCountPerIPv6Network(t *testing.T) {
	l := NewLimiter(newClock().now)
	for i := range maxFailures {
		l.Fail(fmt.Sprintf("2001:db8:1:2::%x", i+1))
	}
	if l.Allow("2001:db8:1:2:ffff::1") {
		t.Error("another address of the same /64 was let through")
	}
	if !l.Allow("2001:db8:1:3::1") || !l.Allow("10.0.0.1") {
		t.Error("another network was held back")
	}
}

// Each device of a user gets its own small number, kept through renewals; numbers of revoked devices are used again
// only once every other number was had.
func TestDeviceNumbers(t *testing.T) {
	c := newClock()
	s := newTestService(t, c)
	enrollAs := func(user string) Device {
		t.Helper()
		code, _ := s.Codes.Create(user)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		enrolled, rejection, err := s.Enroll("10.0.0.2", Request{Code: code, DeviceName: "Pixel", CSR: csrFor(t, key, "x")})
		if err != nil || rejection != "" {
			t.Fatalf("enroll: %v %v", rejection, err)
		}
		return enrolled.Device
	}
	first, second := enrollAs("hen"), enrollAs("hen")
	if first.DeviceNumber != 1 || second.DeviceNumber != 2 || enrollAs("dana").DeviceNumber != 1 {
		t.Fatalf("numbers: %d %d", first.DeviceNumber, second.DeviceNumber)
	}
	if found, _ := s.Registry.Find(second.Serial); found.DeviceNumber != 2 {
		t.Fatalf("registry: %+v", found)
	}

	// A renewal keeps the number; revoking the device revokes the renewal too.
	c.t = first.ExpiresAt.Add(-RenewBefore)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	renewed, rejection, err := s.Renew(first.Serial, csrFor(t, k, "x"), "")
	if err != nil || rejection != "" || renewed.Device.DeviceNumber != 1 || renewed.Device.KeyProtection != first.KeyProtection {
		t.Fatalf("renew: %+v %v %v", renewed.Device, rejection, err)
	}
	if _, err := s.Registry.RevokeDevice(first.Serial, c.t); err != nil {
		t.Fatal(err)
	}
	if !s.Registry.IsRevoked(renewed.Device.Serial) || s.Registry.IsRevoked(second.Serial) {
		t.Fatal("RevokeDevice revoked the wrong certificates")
	}

	// Number 1 is revoked, but never-used numbers go first.
	if third := enrollAs("hen"); third.DeviceNumber != 3 {
		t.Fatalf("after a revocation: %d", third.DeviceNumber)
	}
	for n := 4; n <= MaxDeviceNumber; n++ {
		enrollAs("hen")
	}
	if again := enrollAs("hen"); again.DeviceNumber != 1 {
		t.Fatalf("once every number was had: %d", again.DeviceNumber)
	}
	code, _ := s.Codes.Create("hen")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, _, err := s.Enroll("10.0.0.2", Request{Code: code, CSR: csrFor(t, key, "x")}); !errors.Is(err, ErrTooManyDevices) {
		t.Fatalf("a 128th device: %v", err)
	}
	if n, err := s.Registry.RevokeUser("hen", c.t); err != nil || n != MaxDeviceNumber {
		t.Fatalf("RevokeUser = %d, %v", n, err)
	}
}

// A code made for a user who was removed before it was used enrolls nothing.
func TestARemovedUsersCodeIsInvalid(t *testing.T) {
	s := newTestService(t, newClock())
	removed := false
	s.UserExists = func(name string) bool { return name == "hen" && !removed }
	code, _ := s.Codes.Create("hen")
	removed = true
	if _, r := s.Preview("10.0.0.2", code); r != RejectInvalidCode {
		t.Fatalf("preview: %q", r)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, r, err := s.Enroll("10.0.0.2", Request{Code: code, CSR: csrFor(t, key, "x")}); r != RejectInvalidCode || err != nil {
		t.Fatalf("enroll: %q %v", r, err)
	}
}
