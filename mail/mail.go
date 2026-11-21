// Package mail sends the server's few emails: the codes that prove a friend owns the address an invite is redeemed
// with (docs/authentication.md, "Invites"). Through the Gmail API when config.json has "gmail" (a send-only grant,
// no password kept), over SMTP when it has "smtp"; else the code goes to the server's log, which is enough to try
// invites on a home server before mail is set up.
package mail

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Sender sends one plain-text email.
type Sender interface {
	Send(to, subject, body string) error
}

// Config is config.json's "smtp": where the server sends its mail from. Gmail works with an app password
// (smtp.gmail.com, 587); so does any provider's SMTP relay.
type Config struct {
	Host string `json:"host"`
	// 587 (STARTTLS, the default) or 465 (TLS from the start).
	Port int `json:"port"`
	// The account to sign in with; empty for a relay that takes mail without signing in.
	Username string `json:"username"`
	// A file holding the password (or app password), so it isn't in config.json.
	PasswordFile string `json:"password_file"`
	// The From address, e.g. "Talk <talk@example.com>"; the username when empty.
	From string `json:"from"`
}

// New is the sender config.json asks for: Gmail, SMTP, or the log when it has neither.
func New(config *Config, gmail *GmailConfig) (Sender, error) {
	if gmail != nil {
		if config != nil && config.Host != "" {
			return nil, errors.New("set either gmail or smtp, not both")
		}
		return NewGmail(*gmail)
	}
	if config == nil || config.Host == "" {
		return Log{}, nil
	}
	s := &SMTP{config: *config}
	if s.config.Port == 0 {
		s.config.Port = 587
	}
	if s.config.From == "" {
		s.config.From = s.config.Username
	}
	if _, err := mail.ParseAddress(s.config.From); err != nil {
		return nil, fmt.Errorf("smtp.from %q: %w", s.config.From, err)
	}
	if config.PasswordFile != "" {
		data, err := os.ReadFile(config.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("smtp.password_file: %w", err)
		}
		s.password = strings.TrimSpace(string(data))
	}
	return s, nil
}

// Log writes each email to the server's log instead of sending it.
type Log struct{}

func (Log) Send(to, subject, body string) error {
	log.Printf("Mail (no smtp in config.json, so it is only logged) to %s: %s\n%s", to, subject, body)
	return nil
}

// SMTP sends through an SMTP server.
type SMTP struct {
	config   Config
	password string
}

const smtpTimeout = 30 * time.Second

func (s *SMTP) Send(to, subject, body string) error {
	from, _ := mail.ParseAddress(s.config.From)
	addr := net.JoinHostPort(s.config.Host, fmt.Sprint(s.config.Port))
	tlsConfig := &tls.Config{ServerName: s.config.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: smtpTimeout}
	if s.config.Port == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(smtpTimeout))
	c, err := smtp.NewClient(conn, s.config.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if s.config.Port != 465 {
		// Never sign in or send a code in the clear.
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("the SMTP server doesn't offer STARTTLS")
		}
		if err := c.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if s.config.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.config.Username, s.password, s.config.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	message := "From: " + s.config.From + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + mimeHeader(subject) + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n")
	if _, err := w.Write([]byte(message)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// mimeHeader encodes a subject that isn't plain ASCII (RFC 2047).
func mimeHeader(s string) string {
	for _, r := range s {
		if r > 126 {
			return "=?utf-8?b?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?="
		}
	}
	return s
}
