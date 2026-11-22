package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const renewMutation = `mutation($csr: String!) {
	renewCertificate(csr: $csr, keyProtection: TEE) {
		__typename
		... on EnrolledDevice { user deviceName deviceNumber certificate serial expiresAt }
		... on EnrollmentRejected { reason }
	}
}`

// A device renews its certificate with a new key: the same user, device and device number; the old certificate
// works until the new one is used, then never again.
func TestADeviceRenewsItsCertificate(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "hen")
	env.device(t, "hen") // device 1
	oldClient, enrolled, oldCert := env.device(t, "hen")
	if info := env.graphql(t, oldClient, `{ serverInfo { renewCertificates } }`, nil); !strings.Contains(string(info.Data["serverInfo"]), "true") {
		t.Fatalf("serverInfo: %s", info.Data["serverInfo"])
	}

	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := csrOf(t, newKey)
	resp := env.graphql(t, oldClient, renewMutation, map[string]any{"csr": csr})
	var renewed struct {
		Typename     string `json:"__typename"`
		User         string
		DeviceName   string
		DeviceNumber int
		Certificate  string
		Serial       string
		ExpiresAt    time.Time
	}
	if len(resp.Errors) > 0 || json.Unmarshal(resp.Data["renewCertificate"], &renewed) != nil || renewed.Typename != "EnrolledDevice" {
		t.Fatalf("renew: %s %+v", resp.Data["renewCertificate"], resp.Errors)
	}
	// (The test CA lasts a day, which caps the certificate, so the renewal is in its last 30 days.)
	if renewed.User != "hen" || renewed.DeviceName != "Pixel 9 Pro" || renewed.DeviceNumber != 2 || renewed.Serial == enrolled.Serial ||
		time.Until(renewed.ExpiresAt) < 20*time.Hour {
		t.Errorf("the renewed certificate: %+v", renewed)
	}
	device, _ := env.enrollment.Registry.Find(renewed.Serial)
	if device.RenewedFrom != enrolled.Serial || device.KeyProtection != "TEE" || device.DeviceNumber != 2 {
		t.Errorf("the renewed device: %+v", device)
	}

	// The old certificate still works (the device hasn't switched yet)...
	if r := env.graphql(t, oldClient, `{ me { user } }`, nil); len(r.Errors) > 0 || r.Status != 200 {
		t.Fatalf("the old certificate before the switch: %+v", r)
	}
	// ...until the new one is used.
	newDER, _ := base64.StdEncoding.DecodeString(renewed.Certificate)
	newClient := env.client(&tls.Certificate{Certificate: [][]byte{newDER}, PrivateKey: newKey})
	if r := env.graphql(t, newClient, `{ me { deviceNumber } }`, nil); r.Status != 200 || string(r.Data["me"]) != `{"deviceNumber":2}` {
		t.Fatalf("the new certificate: %+v", r)
	}
	oldClient = env.client(&oldCert) // a new connection
	if r := env.graphql(t, oldClient, `{ me { user } }`, nil); r.Status != 401 {
		t.Errorf("the old certificate after the switch: %d %+v", r.Status, r.Errors)
	}
	// One made outside enrollment (not in the registry) can't renew.
	env.config.EnrolledOnly = false
	outsideKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	outsideCSR, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, outsideKey)
	parsed, _ := x509.ParseCertificateRequest(outsideCSR)
	outside, err := env.enrollment.Issuer.Issue(parsed, "hen")
	if err != nil {
		t.Fatal(err)
	}
	outsideClient := env.client(&tls.Certificate{Certificate: [][]byte{outside.Raw}, PrivateKey: outsideKey})
	if r := env.graphql(t, outsideClient, renewMutation, map[string]any{"csr": csr}); r.Status != 401 {
		t.Errorf("a certificate from outside enrollment with enrolled_only: %d", r.Status)
	}
}
