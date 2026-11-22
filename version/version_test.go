package version

import (
	"regexp"
	"strings"
	"testing"
)

// A version is MAJOR.MINOR.PATCH (docs/install.md "Versions").
func TestNumberIsASemanticVersion(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(Number) {
		t.Fatalf("version/VERSION is %q, not MAJOR.MINOR.PATCH", Number)
	}
	if !strings.HasPrefix(String(), Number) {
		t.Errorf("String() = %q, doesn't start with %s", String(), Number)
	}
}
