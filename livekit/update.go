package livekit

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Updating livekit-server (`ptt-server livekit update`): the release is taken from LiveKit's GitHub releases, its
// archive for this OS and processor is checked against the release's checksums file, and the program in it replaces
// the one ptt-server runs. The running server then restarts LiveKit (the admin API's restartLiveKit).

// ReleasesAPI is LiveKit's releases on GitHub's API.
const ReleasesAPI = "https://api.github.com/repos/livekit/livekit/releases"

// maxDownload bounds an archive (LiveKit's are about 20 MB).
const maxDownload = 200 << 20

// Release is a LiveKit release: its tag (v1.13.11) and its files.
type Release struct {
	Tag    string  `json:"tag_name"`
	Assets []Asset `json:"assets"`
}

// Asset is one file of a release.
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

// Updater fetches and installs livekit-server.
type Updater struct {
	// API is ReleasesAPI, or a test server.
	API  string
	HTTP *http.Client
	// OS and Arch pick the archive (runtime.GOOS and GOARCH when empty).
	OS, Arch string
	// Version runs a livekit-server program and answers its version (ProgramVersion when nil).
	Version func(program string) (string, error)
}

func (u *Updater) client() *http.Client {
	if u.HTTP != nil {
		return u.HTTP
	}
	return &http.Client{Timeout: 5 * time.Minute}
}

func (u *Updater) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ptt-server")
	resp, err := u.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s: more than %d bytes", url, limit)
	}
	return body, nil
}

// Find is the release with tag ("v1.13.11" or "1.13.11"), or the latest one when tag is empty.
func (u *Updater) Find(ctx context.Context, tag string) (Release, error) {
	api := u.API
	if api == "" {
		api = ReleasesAPI
	}
	url := api + "/latest"
	if tag != "" {
		url = api + "/tags/v" + strings.TrimPrefix(tag, "v")
	}
	body, err := u.get(ctx, url, 1<<20)
	if err != nil {
		return Release{}, err
	}
	var r Release
	if err := json.Unmarshal(body, &r); err != nil {
		return Release{}, fmt.Errorf("LiveKit's release: %w", err)
	}
	if r.Tag == "" {
		return Release{}, errors.New("LiveKit's release has no tag")
	}
	return r, nil
}

// Archive is the release's archive for goos and goarch (livekit_1.13.11_windows_amd64.zip) and its checksums file.
func (r Release) Archive(goos, goarch string) (archive, checksums Asset, err error) {
	for _, a := range r.Assets {
		name := strings.ToLower(a.Name)
		switch {
		case strings.HasSuffix(name, "checksums.txt"):
			checksums = a
		case strings.Contains(name, "_"+goos+"_"+goarch+".") &&
			(strings.HasSuffix(name, ".zip") || strings.HasSuffix(name, ".tar.gz")):
			archive = a
		}
	}
	if archive.URL == "" {
		return Asset{}, Asset{}, fmt.Errorf("LiveKit %s has no download for %s/%s", r.Tag, goos, goarch)
	}
	if checksums.URL == "" {
		return Asset{}, Asset{}, fmt.Errorf("LiveKit %s has no checksums file, so its download can't be checked", r.Tag)
	}
	return archive, checksums, nil
}

// checkSum checks data against the line for name in a checksums file ("<sha256 hex>  <name>").
func checkSum(data []byte, name string, checksums []byte) error {
	sum := sha256.Sum256(data)
	s := bufio.NewScanner(bytes.NewReader(checksums))
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			if !strings.EqualFold(fields[0], hex.EncodeToString(sum[:])) {
				return fmt.Errorf("%s doesn't match the release's checksum", name)
			}
			return nil
		}
	}
	return fmt.Errorf("the release's checksums file doesn't list %s", name)
}

// programName is livekit-server's file name on goos.
func programName(goos string) string {
	if goos == "windows" {
		return "livekit-server.exe"
	}
	return "livekit-server"
}

// extract is the program (livekit-server, or livekit-server.exe) out of a .zip or .tar.gz archive.
func extract(archiveName string, data []byte, program string) ([]byte, error) {
	if strings.HasSuffix(strings.ToLower(archiveName), ".zip") {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, err
		}
		for _, f := range zr.File {
			if path.Base(f.Name) == program && !f.FileInfo().IsDir() {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				defer rc.Close()
				return io.ReadAll(io.LimitReader(rc, maxDownload))
			}
		}
		return nil, fmt.Errorf("%s holds no %s", archiveName, program)
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s holds no %s", archiveName, program)
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == program {
			return io.ReadAll(io.LimitReader(tr, maxDownload))
		}
	}
}

var versionPattern = regexp.MustCompile(`\d+\.\d+\.\d+`)

// ProgramVersion runs program --version and answers the version it prints ("1.13.11").
func ProgramVersion(program string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, program, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s --version: %v %s", program, err, strings.TrimSpace(string(out)))
	}
	v := versionPattern.FindString(string(out))
	if v == "" {
		return "", fmt.Errorf("%s --version printed no version: %s", program, strings.TrimSpace(string(out)))
	}
	return v, nil
}

// Installed is what Update did: the version before ("" when there was no program) and now.
type Installed struct {
	Old, New string
	// Same is true when the program already was that version, and nothing changed.
	Same bool
}

// Update puts the release with tag (the latest when empty) at program, the livekit-server ptt-server runs. The new
// program is written beside it, checked to run, and then renamed into place; the old one is kept as <program>.old
// (Windows lets a running program be renamed, not overwritten).
func (u *Updater) Update(ctx context.Context, program, tag string) (Installed, error) {
	version := u.Version
	if version == nil {
		version = ProgramVersion
	}
	goos, goarch := u.OS, u.Arch
	if goos == "" {
		goos, goarch = runtime.GOOS, runtime.GOARCH
	}
	var done Installed
	if _, err := os.Stat(program); err == nil {
		if v, err := version(program); err == nil {
			done.Old = v
		}
	}
	r, err := u.Find(ctx, tag)
	if err != nil {
		return done, err
	}
	want := strings.TrimPrefix(r.Tag, "v")
	if done.Old == want {
		done.New, done.Same = want, true
		return done, nil
	}
	archive, sums, err := r.Archive(goos, goarch)
	if err != nil {
		return done, err
	}
	data, err := u.get(ctx, archive.URL, maxDownload)
	if err != nil {
		return done, err
	}
	sumFile, err := u.get(ctx, sums.URL, 1<<20)
	if err != nil {
		return done, err
	}
	if err := checkSum(data, archive.Name, sumFile); err != nil {
		return done, err
	}
	binary, err := extract(archive.Name, data, programName(goos))
	if err != nil {
		return done, err
	}
	next := program + ".new"
	if err := os.WriteFile(next, binary, 0o755); err != nil {
		return done, err
	}
	got, err := version(next)
	if err != nil {
		os.Remove(next)
		return done, fmt.Errorf("the new livekit-server doesn't run: %w", err)
	}
	if got != want {
		os.Remove(next)
		return done, fmt.Errorf("the new livekit-server says it is %s, not %s", got, want)
	}
	if _, err := os.Stat(program); err == nil {
		os.Remove(program + ".old") // may fail on Windows while an older one still runs; the rename then says so
		if err := os.Rename(program, program+".old"); err != nil {
			os.Remove(next)
			return done, fmt.Errorf("keeping the old livekit-server: %w", err)
		}
	}
	if err := os.Rename(next, program); err != nil {
		os.Rename(program+".old", program)
		return done, err
	}
	done.New = got
	return done, nil
}
