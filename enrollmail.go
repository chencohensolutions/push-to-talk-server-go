package main

import (
	"errors"
	"fmt"
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

// enrollmentMail is the email with a user's enrollment link: the link, and the server and code to type when the mail
// app doesn't open ptt:// links.
func enrollmentMail(user auth.User, code string, expiresAt time.Time, serverURL *string, found *enrollDiscovery) (string, string) {
	name := user.DisplayName
	if name == "" {
		name = user.Name
	}
	body := fmt.Sprintf("Hi %s,\n\nOpen this link on your phone to enroll it with the Talk server:\n\n%s\n\n",
		name, enrollmentLink(code, serverURL, found))
	body += "If it doesn't open, copy the link and paste it in Talk's Enroll screen, or type these there:\n\n"
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
