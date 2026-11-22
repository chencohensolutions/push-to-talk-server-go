package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/certs"
	"github.com/chencohensolutions/push-to-talk-server-go/livekit"
)

func init() {
	certs.UseSmallKeysForTests()
	// Setup downloads LiveKit when it isn't beside ptt-server: not from the tests (a closed port, so it gives up).
	setupLiveKitUpdater = func() *livekit.Updater { return &livekit.Updater{API: "http://127.0.0.1:1"} }
}

// hashTree is every file under dir (relative path → sha256), to show setup changed nothing there.
func hashTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	sums := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		rel, _ := filepath.Rel(dir, path)
		sums[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sums
}

func runSetupIn(t *testing.T, args ...string) {
	t.Helper()
	o, err := parseSetupArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	if err := setup(context.Background(), o); err != nil {
		t.Fatal(err)
	}
}

func TestSetupNewServer(t *testing.T) {
	t.Chdir(t.TempDir())
	base := t.TempDir()
	dir := filepath.Join(base, "server")
	runSetupIn(t, "--dir", dir, "--user", "hen", "--address", "192.168.50.9")

	config, err := auth.LoadConfig(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if config.PublicURL != "https://192.168.50.9:56400" || !config.EnrolledOnly {
		t.Fatalf("config: %+v", config)
	}
	users, err := auth.OpenUsers(filepath.Join(dir, "users.json"))
	if err != nil || users.Find("hen") == nil {
		t.Fatalf("users.json: %v %v", users, err)
	}
	// The server can load what setup made (the same calls serve makes).
	t.Chdir(dir)
	if !config.LiveKitOn() {
		t.Fatal("a new server has no livekit")
	}
	if _, err := livekit.LoadKeys(config.LiveKit.KeysFile); err != nil {
		t.Fatalf("LiveKit's keys: %v", err)
	}
	if yaml, err := os.ReadFile(config.LiveKit.ConfigFile); err != nil || !strings.Contains(string(yaml), "udp_port: 7882") ||
		strings.Contains(string(yaml), "key_file") {
		t.Fatalf("livekit.yaml: %s %v", yaml, err)
	}
	if ports, _ := serverPorts(config); len(ports) != 3 || !ports[1].Exact || ports[1].Port != 7882 {
		t.Fatalf("the ports mapped with LiveKit: %v", ports)
	}
	if _, err := tls.LoadX509KeyPair(config.TLSCert, config.TLSKey); err != nil {
		t.Fatal(err)
	}
	if _, err := createTLSConfig(config); err != nil {
		t.Fatal(err)
	}
	if s, err := openServer(config); err != nil {
		t.Fatal(err)
	} else {
		s.store.Close() // Windows can't remove the folder with the database open
	}
	if _, err := openDiscovery(config); err != nil {
		t.Fatal(err)
	}

	// Running it again changes nothing that is there.
	before := hashTree(t, base)
	runSetupIn(t, "--dir", dir, "--user", "hen", "--address", "192.168.50.9")
	if after := hashTree(t, base); !maps.Equal(before, after) {
		t.Errorf("a second setup changed files:\nbefore %v\nafter  %v", before, after)
	}
}

// A new server needs no user: they are added once it runs (ptt-server user add).
func TestSetupWithoutAUser(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := filepath.Join(t.TempDir(), "server")
	runSetupIn(t, "--dir", dir, "--port", "56500")
	config, err := auth.LoadConfig(filepath.Join(dir, "config.json"))
	if err != nil || config.Port != "56500" {
		t.Fatalf("config: %+v %v", config, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "certs", "ca.pem")); err != nil {
		t.Fatal(err)
	}
}

func TestSetupMoveFromOnlyReadsTheOldServer(t *testing.T) {
	t.Chdir(t.TempDir())
	base := t.TempDir()
	old := filepath.Join(base, "old")
	runSetupIn(t, "--dir", old, "--user", "hen")
	for name, content := range map[string]string{"devices.json": `[]`, "devices.revoked.json": `{}`, "admin.token": "secret"} {
		if err := os.WriteFile(filepath.Join(old, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := hashTree(t, base)

	dir := filepath.Join(base, "new")
	runSetupIn(t, "--dir", dir, "--move-from", old)

	after := hashTree(t, base)
	for path, sum := range before {
		if after[path] != sum {
			t.Errorf("%s changed", path)
		}
	}
	for _, name := range []string{"config.json", "users.json", "devices.json", "devices.revoked.json", "certs/ca.pem",
		"certs/ca-key.pem", "certs/server.pem", "certs/server-key.pem"} {
		want := before[filepath.Join("old", filepath.FromSlash(name))]
		if got := after[filepath.Join("new", filepath.FromSlash(name))]; got != want || got == "" {
			t.Errorf("%s not copied as it was", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "admin.token")); err == nil {
		t.Error("admin.token was copied")
	}

	// Moving into the old folder itself is refused.
	o, err := parseSetupArgs([]string{"--dir", old, "--move-from", old})
	if err != nil {
		t.Fatal(err)
	}
	if err := setup(context.Background(), o); err == nil {
		t.Error("setup moved a server into its own folder")
	}
}

func TestSetupReissueKeepsTheOldServerCertificate(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := filepath.Join(t.TempDir(), "server")
	runSetupIn(t, "--dir", dir)
	old, err := os.ReadFile(filepath.Join(dir, "certs", "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	runSetupIn(t, "--dir", dir, "--address", "10.1.2.3", "--reissue-server-cert")
	backup, err := os.ReadFile(filepath.Join(dir, "certs", "server.pem.bak"))
	if err != nil || string(backup) != string(old) {
		t.Fatalf("old certificate not kept as .bak: %v", err)
	}
}

func TestSetupRefusesUnclearRequests(t *testing.T) {
	for _, args := range [][]string{
		{"--move-from", "x", "--new-ca"},
		{"--import-ca", "x", "--new-ca"},
		{"--user", "../x"},
		{"stray"},
	} {
		if _, err := parseSetupArgs(args); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}

// A new server gets its own CA without being asked; a server that has one never gets another by itself.
func TestSetupMakesEachServerItsOwnCA(t *testing.T) {
	t.Chdir(t.TempDir())
	base := t.TempDir()
	dir := filepath.Join(base, "server")
	runSetupIn(t, "--dir", dir, "--user", "hen")
	other := filepath.Join(base, "other")
	runSetupIn(t, "--dir", other, "--user", "dana")
	mine, _ := os.ReadFile(filepath.Join(dir, "certs", "ca.pem"))
	theirs, _ := os.ReadFile(filepath.Join(other, "certs", "ca.pem"))
	if len(mine) == 0 || string(mine) == string(theirs) {
		t.Fatal("two servers have the same CA")
	}

	// The CA lost from a server with devices: setup refuses rather than make another.
	if err := os.Remove(filepath.Join(dir, "certs", "ca.pem")); err != nil {
		t.Fatal(err)
	}
	o, _ := parseSetupArgs([]string{"--dir", dir})
	if err := setup(context.Background(), o); err == nil || !strings.Contains(err.Error(), "no CA") {
		t.Fatalf("setup without the CA: %v", err)
	}
	// Another server's CA can be taken in.
	runSetupIn(t, "--dir", filepath.Join(base, "third"), "--import-ca", filepath.Join(other, "certs"))
	third, _ := os.ReadFile(filepath.Join(base, "third", "certs", "ca.pem"))
	if string(third) != string(theirs) {
		t.Fatal("--import-ca didn't copy the CA")
	}
}
