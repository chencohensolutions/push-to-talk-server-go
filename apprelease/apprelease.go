// Package apprelease follows the Talk app's releases on GitHub, so that phones are told about an update instead of
// each one asking GitHub on a timer (2026-11-22, hen). Once an hour the server reads the repository's latest release
// (pre-releases, the dev builds, are left out by GitHub's "latest"), takes its APK and the APK's SHA-256 from the
// release's SHA256SUMS, and keeps it in app-release.json. A release it hadn't seen before is announced: the server
// pushes "app_update" to every phone (docs/install.md, "App updates"), and appRelease answers it.
package apprelease

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DefaultRepo is where the app is released.
const DefaultRepo = "chencohensolutions/push-to-talk-kmp"

// API is GitHub's API.
const API = "https://api.github.com"

// Every is how often the releases are read.
const Every = time.Hour

// maxAnswer bounds GitHub's answers (a release's JSON, SHA256SUMS).
const maxAnswer = 1 << 20

// Release is one release of the app: what a phone needs to fetch and check it.
type Release struct {
	// The release's tag (v1.0.2) and the version in it (1.0.2).
	Tag     string `json:"tag"`
	Version string `json:"version"`
	// The APK's file name, address, size and SHA-256 (hex, from SHA256SUMS).
	APKName string `json:"apk_name"`
	APKURL  string `json:"apk_url"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
	// The release's notes (Markdown), and when it was published.
	Notes       string    `json:"notes,omitempty"`
	PublishedAt time.Time `json:"published_at"`
}

// Watcher reads the releases and announces a new one.
type Watcher struct {
	// Repo is owner/name (DefaultRepo); API is GitHub's API, or a test server.
	Repo string
	API  string
	HTTP *http.Client
	// File keeps the latest release seen (app-release.json), so a restart doesn't announce it again.
	File string
	// Announce is called with a release the server hadn't seen (not the first one it ever sees).
	Announce func(Release)

	mu     sync.RWMutex
	latest *Release
}

// Open is a watcher of repo that keeps what it saw in file.
func Open(repo, file string, announce func(Release)) (*Watcher, error) {
	w := &Watcher{Repo: repo, API: API, File: file, Announce: announce}
	data, err := os.ReadFile(file)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		var r Release
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		w.latest = &r
	}
	return w, nil
}

// Latest is the newest release seen, or nil before the first read.
func (w *Watcher) Latest() *Release {
	if w == nil {
		return nil
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.latest == nil {
		return nil
	}
	r := *w.latest
	return &r
}

// Run reads the releases at start and every Every until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	ticker := time.NewTicker(Every)
	defer ticker.Stop()
	for {
		if err := w.Check(ctx); err != nil {
			log.Printf("App releases: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Check reads the latest release once, keeps it, and announces it when it is new. A release without an APK and its
// line in SHA256SUMS is skipped (it may still be uploading), and tried again next time.
func (w *Watcher) Check(ctx context.Context) error {
	r, err := w.fetch(ctx)
	if err != nil {
		return err
	}
	w.mu.Lock()
	previous := w.latest
	if previous != nil && previous.Tag == r.Tag && previous.SHA256 == r.SHA256 {
		w.mu.Unlock()
		return nil
	}
	w.latest = &r
	w.mu.Unlock()
	if err := w.save(r); err != nil {
		return err
	}
	if previous == nil {
		log.Printf("App releases: the latest is %s (%s)", r.Tag, r.APKName)
		return nil // the first one seen: phones that need it find it when the app opens
	}
	log.Printf("App releases: %s is out (was %s): telling the phones", r.Tag, previous.Tag)
	if w.Announce != nil {
		w.Announce(r)
	}
	return nil
}

func (w *Watcher) save(r Release) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(w.File), filepath.Base(w.File)+".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), w.File); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// apkName is the app's file in a release: talk-1.0.2.apk.
var apkName = regexp.MustCompile(`^talk-([0-9][0-9A-Za-z.+-]*)\.apk$`)

func (w *Watcher) fetch(ctx context.Context) (Release, error) {
	api := w.API
	if api == "" {
		api = API
	}
	body, err := w.get(ctx, api+"/repos/"+w.Repo+"/releases/latest")
	if err != nil {
		return Release{}, err
	}
	var gh struct {
		Tag         string    `json:"tag_name"`
		Body        string    `json:"body"`
		Draft       bool      `json:"draft"`
		Prerelease  bool      `json:"prerelease"`
		PublishedAt time.Time `json:"published_at"`
		Assets      []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &gh); err != nil {
		return Release{}, fmt.Errorf("the latest release: %w", err)
	}
	if gh.Draft || gh.Prerelease {
		return Release{}, fmt.Errorf("the latest release %s is a draft or a pre-release", gh.Tag)
	}
	r := Release{Tag: gh.Tag, Notes: gh.Body, PublishedAt: gh.PublishedAt}
	sums := ""
	for _, a := range gh.Assets {
		if m := apkName.FindStringSubmatch(a.Name); m != nil {
			r.APKName, r.APKURL, r.Size, r.Version = a.Name, a.URL, a.Size, m[1]
		}
		if a.Name == "SHA256SUMS" {
			sums = a.URL
		}
	}
	if r.APKURL == "" || sums == "" {
		return Release{}, fmt.Errorf("release %s has no talk-*.apk and SHA256SUMS (yet)", gh.Tag)
	}
	if !strings.HasPrefix(r.APKURL, "https://") {
		return Release{}, fmt.Errorf("release %s: the APK isn't on https", gh.Tag)
	}
	list, err := w.get(ctx, sums)
	if err != nil {
		return Release{}, err
	}
	r.SHA256 = sumOf(list, r.APKName)
	if r.SHA256 == "" {
		return Release{}, fmt.Errorf("release %s: SHA256SUMS has no line for %s", gh.Tag, r.APKName)
	}
	return r, nil
}

// sumOf is the SHA-256 that a SHA256SUMS file (sha256sum's output) gives name, or "".
func sumOf(list []byte, name string) string {
	scanner := bufio.NewScanner(bytes.NewReader(list))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != name {
			continue
		}
		sum := strings.ToLower(fields[0])
		if b, err := hex.DecodeString(sum); err == nil && len(b) == 32 {
			return sum
		}
	}
	return ""
}

func (w *Watcher) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ptt-server")
	req.Header.Set("Accept", "application/vnd.github+json")
	client := w.HTTP
	if client == nil {
		client = &http.Client{Timeout: time.Minute}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxAnswer {
		return nil, fmt.Errorf("%s: over %d bytes", url, maxAnswer)
	}
	return body, nil
}
