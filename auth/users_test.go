package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUsersAreKeptInUsersJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	users, err := OpenUsers(path)
	if err != nil || len(users.List()) != 0 {
		t.Fatalf("a missing file: %v %v", users.List(), err)
	}
	now := time.Date(2026, 11, 21, 10, 0, 0, 0, time.UTC)
	for _, name := range []string{"hen", "dana"} {
		if _, err := users.Add(name, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := users.Add("hen", now); !errors.Is(err, ErrUserExists) {
		t.Fatalf("adding hen twice: %v", err)
	}
	reopened, err := OpenUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	if list := reopened.List(); len(list) != 2 || list[0].Name != "dana" || !list[1].AddedAt.Equal(now) {
		t.Fatalf("reopened: %+v", list)
	}
	if reopened.Find("hen") == nil || reopened.Find("nobody") != nil {
		t.Fatal("Find")
	}
	if _, err := reopened.Remove("hen"); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Remove("hen"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("removing hen twice: %v", err)
	}
	again, _ := OpenUsers(path)
	if again.Find("hen") != nil || again.Find("dana") == nil {
		t.Fatalf("after remove: %+v", again.List())
	}
}

func TestUserNamesAreSafe(t *testing.T) {
	for _, ok := range []string{"hen", "Dana_2", "a.b-c", "חן"} {
		if err := CheckUserName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "a b", "../x", ".hidden", "-x", "a/b", `a\b`, "a:b", "CN=x,O=y", strings.Repeat("a", 33)} {
		if err := CheckUserName(bad); err == nil {
			t.Errorf("%q was taken", bad)
		}
	}
}

func TestADamagedUsersFileStopsTheServer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	for _, text := range []string{"{", `[{"name":"hen"},{"name":"hen"}]`, `[{"name":"../x"}]`} {
		os.WriteFile(path, []byte(text), 0o600)
		if _, err := OpenUsers(path); err == nil {
			t.Errorf("%s was read", text)
		}
	}
}

func TestConfigDefaultsAndUnknownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte(`{"tls_cert": "certs/server.pem"}`), 0o644)
	config, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if config.Port != "56400" || config.AdminAddr != "127.0.0.1:8082" || config.UsersFile != "users.json" ||
		!config.DiscoveryOn() || !config.PortMappingOn() {
		t.Fatalf("defaults: %+v", config)
	}
	os.WriteFile(path, []byte(`{"users": [{"username": "hen", "data_folder": "x"}]}`), 0o644)
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "users") {
		t.Fatalf("a Journal config.json: %v", err)
	}
}
