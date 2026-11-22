package livekit

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func zipOf(name string, data []byte) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	f, _ := w.Create(name)
	f.Write(data)
	w.Close()
	return b.Bytes()
}

func tarGzOf(name string, data []byte) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "LICENSE", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
	tw.Write([]byte("ok"))
	tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg})
	tw.Write(data)
	tw.Close()
	gz.Close()
	return b.Bytes()
}

// fakeReleases serves LiveKit's releases API for version v, with a Windows zip and a Linux tar.gz whose programs
// print "livekit-server version <v>"; badSum spoils the checksum of the Linux archive.
func fakeReleases(t *testing.T, v string, badSum bool) *httptest.Server {
	files := map[string][]byte{
		"livekit_" + v + "_windows_amd64.zip":  zipOf("livekit-server.exe", []byte("livekit-server version "+v)),
		"livekit_" + v + "_linux_amd64.tar.gz": tarGzOf("livekit-server", []byte("livekit-server version "+v)),
	}
	var sums strings.Builder
	for name, data := range files {
		sum := sha256.Sum256(data)
		if badSum && strings.Contains(name, "linux") {
			sum[0] ^= 1
		}
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	files["livekit_"+v+"_checksums.txt"] = []byte(sums.String())
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/releases/latest" || r.URL.Path == "/releases/tags/v"+v {
			rel := Release{Tag: "v" + v}
			for name := range files {
				rel.Assets = append(rel.Assets, Asset{Name: name, URL: srv.URL + "/download/" + name})
			}
			json.NewEncoder(w).Encode(rel)
			return
		}
		if data, ok := files[strings.TrimPrefix(r.URL.Path, "/download/")]; ok {
			w.Write(data)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fileVersion stands in for running the program: the version is in its bytes.
func fileVersion(program string) (string, error) {
	data, err := os.ReadFile(program)
	if err != nil {
		return "", err
	}
	v := regexp.MustCompile(`\d+\.\d+\.\d+`).FindString(string(data))
	if v == "" {
		return "", fmt.Errorf("not a program")
	}
	return v, nil
}

func TestUpdateLiveKit(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	for _, c := range []struct{ os, program string }{{"linux", "livekit-server"}, {"windows", "livekit-server.exe"}} {
		program := filepath.Join(dir, c.program)
		os.WriteFile(program, []byte("livekit-server version 1.13.11"), 0o755)
		u := &Updater{API: fakeReleases(t, "1.14.0", false).URL + "/releases", OS: c.os, Arch: "amd64", Version: fileVersion}
		done, err := u.Update(ctx, program, "")
		if err != nil || done.Old != "1.13.11" || done.New != "1.14.0" || done.Same {
			t.Fatalf("%s: %+v %v", c.os, done, err)
		}
		if v, _ := fileVersion(program); v != "1.14.0" {
			t.Fatalf("%s: the program is %s", c.os, v)
		}
		if v, _ := fileVersion(program + ".old"); v != "1.13.11" {
			t.Fatalf("%s: the old program is %s", c.os, v)
		}
		if done, err := u.Update(ctx, program, "v1.14.0"); err != nil || !done.Same {
			t.Fatalf("%s: updating to the same version: %+v %v", c.os, done, err)
		}
	}

	// A download that doesn't match its checksum changes nothing.
	program := filepath.Join(dir, "livekit-server")
	os.WriteFile(program, []byte("livekit-server version 1.13.11"), 0o755)
	u := &Updater{API: fakeReleases(t, "1.15.0", true).URL + "/releases", OS: "linux", Arch: "amd64", Version: fileVersion}
	if _, err := u.Update(ctx, program, ""); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("a bad checksum: %v", err)
	}
	if v, _ := fileVersion(program); v != "1.13.11" {
		t.Fatalf("after a bad checksum the program is %s", v)
	}
	// No download for this processor.
	u = &Updater{API: fakeReleases(t, "1.15.0", false).URL + "/releases", OS: "plan9", Arch: "arm", Version: fileVersion}
	if _, err := u.Update(ctx, program, ""); err == nil || !strings.Contains(err.Error(), "no download") {
		t.Fatalf("no download for the processor: %v", err)
	}
	// A first install: no program there yet.
	fresh := filepath.Join(t.TempDir(), "livekit-server")
	u = &Updater{API: fakeReleases(t, "1.14.0", false).URL + "/releases", OS: "linux", Arch: "amd64", Version: fileVersion}
	if done, err := u.Update(ctx, fresh, ""); err != nil || done.Old != "" || done.New != "1.14.0" {
		t.Fatalf("a first install: %+v %v", done, err)
	}
}
