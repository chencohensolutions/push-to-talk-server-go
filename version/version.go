// Package version is the server's version: version/VERSION, a semantic version (1.0.0), embedded in ptt-server. See
// docs/install.md "Versions".
package version

import (
	_ "embed"
	"runtime/debug"
	"strings"
)

//go:embed VERSION
var file string

// Number is the version in VERSION, e.g. "1.0.0".
var Number = strings.TrimSpace(file)

// String is the version with the build's commit and time from the Go build info: "1.0.0 (3f2a9c1 2026-11-21)",
// with "dirty" when built with uncommitted changes, or just "1.0.0" when built without version control.
func String() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return Number
	}
	var revision, at string
	dirty := false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			at = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if revision == "" {
		return Number
	}
	if len(revision) > 7 {
		revision = revision[:7]
	}
	if len(at) >= 10 {
		revision += " " + at[:10]
	}
	if dirty {
		revision += " dirty"
	}
	return Number + " (" + revision + ")"
}
