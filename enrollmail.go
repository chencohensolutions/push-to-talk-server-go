package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/discovery"
)

// mailEnrollment is how createEnrollmentCode mails a user its enrollment link (config.json "gmail"): the same
// ptt://enroll link the QR code of enroll-code holds, with the server's fingerprint, DHT key and addresses as the
// running server knows them, so the phone pins the server from the first connection.
func (s *server) mailEnrollment() func(user auth.User, code string, expiresAt time.Time) error {
	return func(user auth.User, code string, expiresAt time.Time) error {
		if s.mail == nil {
			return errors.New("the server can't send mail (its log says why): run ptt-server mail-login, then restart the server")
		}
		if user.Email == "" {
			return errors.New("the user has no email")
		}
		var found *enrollDiscovery
		var serverURL *string
		if s.config.PublicURL != "" {
			serverURL = &s.config.PublicURL
		}
		if s.discovery != nil {
			if d := s.discovery(); d != nil {
				found = &enrollDiscovery{Fingerprint: d.Fingerprint, Addresses: d.Addresses}
				if d.Key != nil {
					found.Key = *d.Key
				}
				if serverURL == nil && len(d.Addresses) > 0 {
					serverURL = &d.Addresses[0]
				}
			}
		}
		subject, body := enrollmentMail(user, code, expiresAt, serverURL, found)
		return s.mail.Send(user.Email, subject, body)
	}
}

// webPages is the app repo's GitHub Pages, where a link's web form opens Talk (2026-11-24, hen: Gmail drops ptt://
// links, so the mail's link couldn't be tapped).
const webPages = "https://chencohensolutions.github.io/push-to-talk-server-go/"

// webLink is a ptt://<kind>?<query> link's web form, <webPages><kind>#<query>: the words after # stay in the phone
// (a browser never sends the fragment), and the page there hands them to Talk. Any other text is left as it is.
func webLink(link string) string {
	const scheme = "ptt://"
	if !strings.HasPrefix(link, scheme) {
		return link
	}
	rest := link[len(scheme):]
	i := strings.Index(rest, "?")
	if i <= 0 {
		return link
	}
	return webPages + rest[:i] + "#" + rest[i+1:]
}

// enrollmentMail is the email with a user's enrollment link: its web form (mail apps let you tap an https link, not a
// ptt:// one), then the ptt:// link itself and the server and code to type when that doesn't open.
func enrollmentMail(user auth.User, code string, expiresAt time.Time, serverURL *string, found *enrollDiscovery) (string, string) {
	name := user.DisplayName
	if name == "" {
		name = user.Name
	}
	link := enrollmentLink(code, serverURL, found)
	body := fmt.Sprintf("Hi %s,\n\nOpen this link on your phone to enroll it with the Talk server:\n\n%s\n\n",
		name, webLink(link))
	body += "If it doesn't open, copy this link and paste it in Talk's Enroll screen:\n\n" + link + "\n\nor type these there:\n\n"
	if serverURL != nil {
		body += "  Server   " + *serverURL + "\n"
	}
	if found != nil {
		body += "  Id       " + discovery.FormatID(found.Fingerprint) + "\n"
	}
	body += "  Code     " + code + "\n\n"
	body += fmt.Sprintf("It works once, until %s (%d minutes). If you didn't ask for it, ignore this email: without the "+
		"code nobody can enroll as you.\n", expiresAt.Local().Format("15:04 MST"),
		int(time.Until(expiresAt).Round(time.Minute).Minutes()))
	return "Talk: enroll your phone", body
}
