// Package mail sends the server's emails: the enrollment links of docs/authentication.md, "Enrollment by email".
// They go through the Gmail API as the account `ptt-server mail-login` signed in with, holding a send-only grant
// and no password (2026-11-22, hen: "the server will send enrollment via email only. don't store my password").
// Without "gmail" in config.json the server has no Sender, and enrollment falls back to codes the admin prints.
package mail

import (
	"encoding/base64"
	"log"
	"strings"
	"time"
)

// Sender sends one plain-text email.
type Sender interface {
	Send(to, subject, body string) error
}

// Log writes the mail to the server's log instead of sending it: for tests, never for a real server, since an
// enrollment link in a log is as good as the mail.
type Log struct{}

func (Log) Send(to, subject, body string) error {
	log.Printf("Mail to %s: %s\n%s", to, subject, strings.TrimSpace(body))
	return nil
}

// timeout bounds each call to Google.
const timeout = 30 * time.Second

// mimeHeader encodes a subject that isn't plain ASCII (RFC 2047).
func mimeHeader(s string) string {
	for _, r := range s {
		if r > 126 {
			return "=?utf-8?b?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
		}
	}
	return s
}
