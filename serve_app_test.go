package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeReleases is GitHub's API for one repository's latest release and its files.
type fakeReleases struct {
	*httptest.Server
	mu      sync.Mutex
	version string
	sum     string
}

func newFakeReleases(t *testing.T) *fakeReleases {
	t.Helper()
	f := &fakeReleases{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/owner/talk/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.version == "" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v" + f.version, "body": "Talk " + f.version, "published_at": "2026-11-22T13:00:00Z",
			"assets": []map[string]any{
				{"name": "SHA256SUMS", "browser_download_url": f.URL + "/download/v" + f.version + "/SHA256SUMS", "size": 80},
				{"name": "talk-" + f.version + ".apk", "browser_download_url": "https://github.example/talk-" + f.version + ".apk", "size": 1234},
			},
		})
	})
	mux.HandleFunc("GET /download/{tag}/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		fmt.Fprintf(w, "%s  talk-%s.apk\n", f.sum, f.version)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

func (f *fakeReleases) publish(version, sum string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version, f.sum = version, sum
}

// The server follows the app's releases: appRelease answers the latest, and a new one is pushed to every phone with
// a token as app_update (the first one the server ever sees isn't: phones find it when the app opens).
func TestANewAppReleaseIsPushedToThePhones(t *testing.T) {
	env, fcm := newPushEnv(t)
	releases := newFakeReleases(t)
	env.appReleases.API, env.appReleases.Repo = releases.URL, "owner/talk"
	env.addUser(t, "hen")
	env.addUser(t, "dana")
	hen, dana := env.phone(t, "hen"), env.phone(t, "dana")
	env.registerPush(t, hen, "hen-token", true)
	env.registerPush(t, dana, "dana-token", false)

	query := `{ appRelease { tag version apkUrl size sha256 notes } }`
	if r := env.graphql(t, hen.client, query, nil); string(r.Data["appRelease"]) != `null` {
		t.Fatalf("before the releases are read: %s %v", r.Data, r.Errors)
	}
	ctx := context.Background()
	if _, err := env.appReleases.Check(ctx, false); err == nil {
		t.Fatal("no release yet: want an error")
	}

	sum1 := "aa000000000000000000000000000000000000000000000000000000000000aa"
	releases.publish("1.0.2", sum1)
	if _, err := env.appReleases.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	fcm.none(t, 100*time.Millisecond)
	var answer struct {
		Tag, Version, ApkURL, Sha256, Notes string
		Size                                int
	}
	r := env.graphql(t, dana.client, query, nil)
	if err := json.Unmarshal(r.Data["appRelease"], &answer); err != nil || answer.Version != "1.0.2" ||
		answer.Sha256 != sum1 || answer.Size != 1234 || answer.Notes != "Talk 1.0.2" ||
		answer.ApkURL != "https://github.example/talk-1.0.2.apk" {
		t.Fatalf("appRelease: %s %v", r.Data, r.Errors)
	}

	// The same release again: nothing is pushed. A new one: both phones are told, quietly.
	if _, err := env.appReleases.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	fcm.none(t, 100*time.Millisecond)
	releases.publish("1.0.3", "bb000000000000000000000000000000000000000000000000000000000000bb")
	if _, err := env.appReleases.Check(ctx, false); err != nil {
		t.Fatal(err)
	}
	tokens := map[string]bool{}
	for range 2 {
		m := fcm.next(t)
		if m.Data["kind"] != "app_update" || m.Android.Priority != "NORMAL" || m.Android.TTL != "604800s" {
			t.Fatalf("the push: %+v", m)
		}
		tokens[m.Token] = true
	}
	if !tokens["hen-token"] || !tokens["dana-token"] {
		t.Fatalf("pushed to %v", tokens)
	}
	fcm.none(t, 100*time.Millisecond)
	if r := env.graphql(t, hen.client, `{ appRelease { version } }`, nil); string(r.Data["appRelease"]) != `{"version":"1.0.3"}` {
		t.Fatalf("appRelease after 1.0.3: %s", r.Data)
	}

	// The admin's `ptt-server app-update`: nothing new, nothing pushed; with --push, every phone is told again.
	check := func(push bool) (out struct {
		Tag    string
		New    bool
		Pushed int
	}) {
		var data struct{ CheckAppRelease json.RawMessage }
		if err := adminQuery(env.adminConfig, `mutation($p: Boolean!) { checkAppRelease(push: $p) { tag new pushed } }`,
			map[string]any{"p": push}, &data); err != nil {
			t.Fatal(err)
		}
		json.Unmarshal(data.CheckAppRelease, &out)
		return out
	}
	if c := check(false); c.Tag != "v1.0.3" || c.New || c.Pushed != 0 {
		t.Fatalf("app-update: %+v", c)
	}
	fcm.none(t, 100*time.Millisecond)
	if c := check(true); c.Tag != "v1.0.3" || c.New || c.Pushed != 2 {
		t.Fatalf("app-update --push: %+v", c)
	}
	for range 2 {
		if m := fcm.next(t); m.Data["kind"] != "app_update" {
			t.Fatalf("the pushed again: %+v", m)
		}
	}
	if err := appUpdateCommand(env.adminConfig, false); err != nil {
		t.Fatal(err)
	}

	// A restart remembers 1.0.3, so it isn't pushed again.
	reopened, err := openServer(env.config)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.store.Close()
	if got := reopened.appReleases.Latest(); got == nil || got.Tag != "v1.0.3" {
		t.Fatalf("after a restart: %+v", got)
	}

	// Without a certificate, appRelease is refused.
	if r := env.graphql(t, env.client(nil), `{ appRelease { version } }`, nil); len(r.Errors) == 0 {
		t.Fatalf("anonymous appRelease: %s", r.Data["appRelease"])
	}
}
