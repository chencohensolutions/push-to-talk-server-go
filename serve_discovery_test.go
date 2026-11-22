package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/chencohensolutions/push-to-talk-server-go/discovery"
)

// forward is a home line in front of the test server: an address that reaches it until closed (the line's IP
// changed).
func forward(t *testing.T, target string) (addr string, closeLine func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var open []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			mu.Lock()
			open = append(open, c, s)
			mu.Unlock()
			go func() { io.Copy(s, c); s.Close() }()
			go func() { io.Copy(c, s); c.Close() }()
		}
	}()
	closeLine = func() {
		ln.Close()
		mu.Lock()
		for _, c := range open {
			c.Close()
		}
		mu.Unlock()
	}
	t.Cleanup(closeLine)
	return ln.Addr().String(), closeLine
}

// pinned is how an enrolled phone trusts the server (docs/authentication.md, "Client side"): the server's key must
// be the fingerprint it was given, or its certificate must chain to the CA it kept; the host name isn't checked, so
// any address works.
func pinned(cert tls.Certificate, fingerprint, caPEM string) *http.Client {
	kept := x509.NewCertPool()
	kept.AppendCertsFromPEM([]byte(caPEM))
	config := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no certificate")
			}
			leaf := cs.PeerCertificates[0]
			if fingerprint != "" {
				if discovery.Fingerprint(leaf) != fingerprint {
					return errors.New("not the server's key")
				}
				return nil
			}
			_, err := leaf.Verify(x509.VerifyOptions{Roots: kept, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		},
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: config}}
}

// The phone reaches the server again after its address changes: at an address its certificate doesn't list, by the
// fingerprint from serverInfo.discovery, or by the CA it kept. Another server at the old address is refused.
func TestAPhoneReconnectsAfterTheAddressChanges(t *testing.T) {
	env := newTestEnv(t)
	env.addUser(t, "hen")
	phone, enrolled, cert := env.device(t, "hen")
	info := env.graphql(t, phone, `{ serverInfo { discovery { fingerprint key } } }`, nil)
	var got struct {
		Discovery struct{ Fingerprint, Key string }
	}
	json.Unmarshal(info.Data["serverInfo"], &got)

	target := strings.TrimPrefix(env.public.URL, "https://")
	first, closeFirst := forward(t, target)
	me := func(client *http.Client, addr string) (string, error) {
		resp, err := client.Post("https://"+addr+"/query", "application/json", strings.NewReader(`{"query":"{ me { user deviceNumber } }"}`))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("%s", resp.Status)
		}
		return string(body), nil
	}
	byKey := pinned(cert, got.Discovery.Fingerprint, "")
	if body, err := me(byKey, first); err != nil || !strings.Contains(body, `"deviceNumber":1`) {
		t.Fatalf("at the first address: %s %v", body, err)
	}

	// The line's IP changes: the old address answers nothing, the new one (found in the DHT) reaches the server.
	closeFirst()
	if _, err := me(pinned(cert, got.Discovery.Fingerprint, ""), first); err == nil {
		t.Fatal("the old address still answers")
	}
	second, _ := forward(t, target)
	for name, client := range map[string]*http.Client{
		"by the fingerprint": pinned(cert, got.Discovery.Fingerprint, ""),
		"by the kept CA":     pinned(cert, "", enrolled.CaCertificate),
	} {
		if body, err := me(client, second); err != nil || !strings.Contains(body, `"user":"hen"`) {
			t.Errorf("%s at the new address: %s %v", name, body, err)
		}
	}

	// Another server answering at an address the phone knows isn't taken for this one.
	other := newTestEnv(t)
	if _, err := me(pinned(cert, got.Discovery.Fingerprint, ""), strings.TrimPrefix(other.public.URL, "https://")); err == nil {
		t.Fatal("another server passed the fingerprint")
	}
	if _, err := me(pinned(cert, "", enrolled.CaCertificate), strings.TrimPrefix(other.public.URL, "https://")); err == nil {
		t.Fatal("another server passed the kept CA")
	}
	if got.Discovery.Key == "" {
		t.Fatal("no DHT key to look the server up by")
	}
}
