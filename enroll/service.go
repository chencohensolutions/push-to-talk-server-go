// Package enroll lets a device trade a one-time enrollment code and a certificate request for a client certificate
// signed by the server's client CA, and keeps the registry of enrolled devices with their device numbers. See
// docs/authentication.md.
package enroll

import (
	"crypto/x509"
	"strings"
	"time"
	"unicode/utf8"
)

// Rejection is an expected enrollment failure, reported to the client as data.
type Rejection string

const (
	// RejectInvalidCode covers wrong, expired and already used codes alike, so guessing learns nothing.
	RejectInvalidCode Rejection = "INVALID_CODE"
	RejectInvalidCSR  Rejection = "INVALID_CSR"
	RejectRateLimited Rejection = "RATE_LIMITED"
	// A renewal from a certificate the registry doesn't know (made outside enrollment), or revoked.
	RejectNotEnrolled Rejection = "NOT_ENROLLED"
)

// RenewBefore is how long before its certificate expires a device renews it.
var RenewBefore = 30 * 24 * time.Hour

// renewEarliest is how long before its certificate expires the server renews it at the earliest: twice the window the
// apps renew in, for a clock that is off. Earlier, a renewal is refused (RATE_LIMITED), so a stolen certificate can't
// be made to last for ever by renewing it.
var renewEarliest = 2 * RenewBefore

// maxRenewals is how many certificates one certificate may be renewed to: a renewal that failed part way is tried
// again (the app keeps the old one until the new one works), but no more often than this.
const maxRenewals = 5

const maxDeviceNameLength = 64

// UserExists reports whether a user may still enroll: one removed after its code was made may not.
type UserExists func(name string) bool

type Service struct {
	Codes    *CodeStore
	Issuer   *Issuer
	Registry *Registry
	// Checked when a code is redeemed; nil takes every user.
	UserExists UserExists
	limiter    *failureLimiter
	now        func() time.Time
}

func NewService(issuer *Issuer, registry *Registry, now func() time.Time) *Service {
	return &Service{
		Codes:    NewCodeStore(now),
		Issuer:   issuer,
		Registry: registry,
		limiter:  newFailureLimiter(now),
		now:      now,
	}
}

type Preview struct {
	User      string
	ExpiresAt time.Time
}

// Preview tells the device which account a code belongs to without using it up.
// Wrong codes count against the client's failure limit, like in Enroll.
func (s *Service) Preview(clientIP, code string) (Preview, Rejection) {
	if !s.limiter.Allow(clientIP) {
		return Preview{}, RejectRateLimited
	}
	pending, ok := s.Codes.Peek(code)
	if !ok || !s.userExists(pending.User) {
		s.limiter.Fail(clientIP)
		return Preview{}, RejectInvalidCode
	}
	return Preview{User: pending.User, ExpiresAt: pending.ExpiresAt}, ""
}

func (s *Service) userExists(name string) bool { return s.UserExists == nil || s.UserExists(name) }

type Request struct {
	Code          string
	DeviceName    string
	CSR           []byte // PKCS#10, DER
	KeyProtection string
}

type Enrolled struct {
	Device      Device
	Certificate []byte // DER
}

// Enroll redeems the code and issues a certificate for the request's key, with the user's next device number. The
// code is only used up once the request itself checked out, so a malformed request does not waste it.
func (s *Service) Enroll(clientIP string, req Request) (Enrolled, Rejection, error) {
	if !s.limiter.Allow(clientIP) {
		return Enrolled{}, RejectRateLimited, nil
	}
	csr, err := ParseDeviceCSR(req.CSR)
	if err != nil {
		return Enrolled{}, RejectInvalidCSR, nil
	}
	pending, ok := s.Codes.Redeem(req.Code)
	if !ok || !s.userExists(pending.User) {
		s.limiter.Fail(clientIP)
		return Enrolled{}, RejectInvalidCode, nil
	}
	enrolled, err := s.issue(pending.User, csr, req)
	return enrolled, "", err
}

// EnrollAs issues a certificate for the request's key as a device of user, with no enrollment code: for a user an
// invite just made, once the invite and the email code checked out (invite.Service). The caller checks the request
// with CheckRequest first.
func (s *Service) EnrollAs(user string, req Request) (Enrolled, error) {
	csr, err := ParseDeviceCSR(req.CSR)
	if err != nil {
		return Enrolled{}, err
	}
	return s.issue(user, csr, req)
}

// CheckRequest says whether req's certificate request is one Enroll takes.
func CheckRequest(req Request) bool {
	_, err := ParseDeviceCSR(req.CSR)
	return err == nil
}

func (s *Service) issue(user string, csr *x509.CertificateRequest, req Request) (Enrolled, error) {
	cert, err := s.Issuer.Issue(csr, user)
	if err != nil {
		return Enrolled{}, err
	}
	device, err := s.Registry.Add(Device{
		Serial:        SerialString(cert.SerialNumber),
		User:          user,
		Name:          cleanDeviceName(req.DeviceName),
		KeyProtection: req.KeyProtection,
		RegisteredAt:  s.now().UTC(),
		ExpiresAt:     cert.NotAfter.UTC(),
	})
	if err != nil { // ErrTooManyDevices among them
		return Enrolled{}, err
	}
	return Enrolled{Device: device, Certificate: cert.Raw}, nil
}

// Renew issues a new certificate for the enrolled device with serial, for the request's key (a new one, made by the
// device): the same user, name and device number. The old certificate works until the new one is first used
// (Registry.UseRenewal).
func (s *Service) Renew(serial string, csrDER []byte, keyProtection string) (Enrolled, Rejection, error) {
	old, ok := s.Registry.Find(serial)
	if !ok || old.RevokedAt != nil {
		return Enrolled{}, RejectNotEnrolled, nil
	}
	if !old.ExpiresAt.IsZero() && old.ExpiresAt.Sub(s.now()) > renewEarliest {
		return Enrolled{}, RejectRateLimited, nil
	}
	renewed := 0
	for _, d := range s.Registry.List(old.User) {
		if d.RenewedFrom == serial {
			renewed++
		}
	}
	if renewed >= maxRenewals {
		return Enrolled{}, RejectRateLimited, nil
	}
	csr, err := ParseDeviceCSR(csrDER)
	if err != nil {
		return Enrolled{}, RejectInvalidCSR, nil
	}
	cert, err := s.Issuer.Issue(csr, old.User)
	if err != nil {
		return Enrolled{}, "", err
	}
	if keyProtection == "" {
		keyProtection = old.KeyProtection
	}
	device, err := s.Registry.Add(Device{
		Serial:               SerialString(cert.SerialNumber),
		User:                 old.User,
		Name:                 old.Name,
		KeyProtection:        keyProtection,
		RegisteredAt:         s.now().UTC(),
		ExpiresAt:            cert.NotAfter.UTC(),
		RenewedFrom:          old.Serial,
		DeviceNumber:         old.DeviceNumber,
		FCMToken:             old.FCMToken,
		NotificationsEnabled: old.NotificationsEnabled,
	})
	if err != nil {
		return Enrolled{}, "", err
	}
	return Enrolled{Device: device, Certificate: cert.Raw}, "", nil
}

func cleanDeviceName(name string) string {
	name = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < ' ' {
			return -1
		}
		return r
	}, name))
	if name == "" {
		return "Unnamed device"
	}
	for utf8.RuneCountInString(name) > maxDeviceNameLength {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	return name
}
