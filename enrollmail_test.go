package main

import (
	"strings"
	"testing"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
)

// The mail's link is the web form (2026-11-24, hen: Gmail drops ptt:// links); the ptt:// link is still in it.
func TestEnrollmentMailLinksTheWebForm(t *testing.T) {
	server := "https://192.168.50.2:56400"
	_, body := enrollmentMail(auth.User{Name: "dana"}, "K7QM-4XPD", time.Now().Add(10*time.Minute), &server, nil)
	app := enrollmentLink("K7QM-4XPD", &server, nil)
	if !strings.Contains(body, "https://chencohensolutions.github.io/push-to-talk-kmp/enroll#") {
		t.Fatalf("no web link in:\n%s", body)
	}
	if !strings.Contains(body, app) {
		t.Fatalf("no ptt:// link in:\n%s", body)
	}
	if got, want := webLink("ptt://enroll?code=x&server=y"), "https://chencohensolutions.github.io/push-to-talk-kmp/enroll#code=x&server=y"; got != want {
		t.Fatalf("webLink = %q, want %q", got, want)
	}
	if got := webLink("https://example.com"); got != "https://example.com" {
		t.Fatalf("webLink changed %q", got)
	}
}
