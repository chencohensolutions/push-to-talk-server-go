package invite

import (
	"crypto/subtle"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/contacts"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
)

// Rejection is an expected failure of an invite, reported to the phone as data.
type Rejection string

const (
	// Wrong, used, canceled or expired invite, alike, so guessing learns nothing.
	RejectInvalidCode  Rejection = "INVALID_CODE"
	RejectInvalidEmail Rejection = "INVALID_EMAIL"
	// The invite is for another email address.
	RejectEmailMismatch Rejection = "EMAIL_MISMATCH"
	// Another user has this email: they enroll a new phone of theirs instead.
	RejectEmailTaken Rejection = "EMAIL_TAKEN"
	// The passcode is wrong; after maxPasscodeTries wrong ones the invite stops working.
	RejectWrongPasscode Rejection = "WRONG_PASSCODE"
	// Too many wrong codes from this address.
	RejectRateLimited Rejection = "RATE_LIMITED"
	RejectInvalidCSR  Rejection = "INVALID_CSR"
	// The inviter opened their own invite.
	RejectOwnInvite Rejection = "OWN_INVITE"
)

// maxPasscodeTries is how many wrong passcodes an invite takes before it stops working: with a million passcodes,
// someone holding only the link has a 1 in 100,000 chance.
const maxPasscodeTries = 10

// Service is the invites: the store, the wrong passcodes, and what redeeming one makes (a user, a device, a pairing
// token).
type Service struct {
	Store      *Store
	Users      *auth.Users
	Enrollment *enroll.Service
	Book       *contacts.Book
	limiter    *enroll.Limiter
	now        func() time.Time

	mu    sync.Mutex
	wrong map[string]int // wrong passcodes, by invite id; in memory, so a restart starts the count again
}

func NewService(store *Store, users *auth.Users, enrollment *enroll.Service, book *contacts.Book, now func() time.Time) *Service {
	return &Service{Store: store, Users: users, Enrollment: enrollment, Book: book, limiter: enroll.NewLimiter(now),
		now: now, wrong: map[string]int{}}
}

// Create makes an invite from by, for email when it isn't empty, and gives its code and its passcode, for the
// inviter's phone to send to the friend.
func (s *Service) Create(by, email string) (Invite, string, string, error) {
	if email != "" {
		normalized, err := NormalizeEmail(email)
		if err != nil {
			return Invite{}, "", "", err
		}
		email = normalized
	}
	invite, code, passcode, err := s.Store.Create(by, email)
	if err == nil {
		log.Printf("Invite %s made by %s (for %s), until %s", invite.ID, by, orAnyone(invite.Email), invite.ExpiresAt.Format(time.DateOnly))
	}
	return invite, code, passcode, err
}

func orAnyone(email string) string {
	if email == "" {
		return "anyone with the link"
	}
	return email
}

// Preview is what a phone shows before redeeming an invite.
type Preview struct {
	Inviter            string
	InviterDisplayName string
	Email              string
	ExpiresAt          time.Time
}

// find is the pending invite with code, counting a wrong one against clientIP.
func (s *Service) find(clientIP, code string) (Invite, Rejection) {
	if !s.limiter.Allow(clientIP) {
		return Invite{}, RejectRateLimited
	}
	invite, ok := s.Store.Find(code)
	if !ok || s.Users.Find(invite.InvitedBy) == nil {
		s.limiter.Fail(clientIP)
		return Invite{}, RejectInvalidCode
	}
	return invite, ""
}

// Preview tells a phone who an invite is from, without using it up.
func (s *Service) Preview(clientIP, code string) (Preview, Rejection) {
	invite, rejection := s.find(clientIP, code)
	if rejection != "" {
		return Preview{}, rejection
	}
	inviter := s.Users.Find(invite.InvitedBy)
	return Preview{Inviter: invite.InvitedBy, InviterDisplayName: inviter.DisplayName, Email: invite.Email,
		ExpiresAt: invite.ExpiresAt}, ""
}

// checkEmail is the email the new user gets, normalized: for an invite with one, email must be it (any case); for
// one without, email is the friend's own, unverified, or empty.
func (s *Service) checkEmail(invite Invite, email string) (string, Rejection) {
	email = strings.TrimSpace(email)
	if email == "" {
		if invite.Email != "" {
			return "", RejectEmailMismatch
		}
		return "", ""
	}
	email, err := NormalizeEmail(email)
	if err != nil {
		return "", RejectInvalidEmail
	}
	if invite.Email != "" && invite.Email != email {
		return "", RejectEmailMismatch
	}
	if s.Users.FindByEmail(email) != nil {
		return "", RejectEmailTaken
	}
	return email, ""
}

// checkPasscode says whether digits (spaces and dashes left out) is the invite's passcode. A wrong one counts against
// the client's address, and the invite stops working after maxPasscodeTries of them.
func (s *Service) checkPasscode(clientIP string, invite Invite, digits string) Rejection {
	digits = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, digits)
	if subtle.ConstantTimeCompare([]byte(invite.PasscodeHash), []byte(hashCode(invite.ID+"/"+digits))) == 1 {
		return ""
	}
	s.limiter.Fail(clientIP)
	s.mu.Lock()
	s.wrong[invite.ID]++
	tooMany := s.wrong[invite.ID] >= maxPasscodeTries
	s.mu.Unlock()
	if tooMany {
		log.Printf("Invite %s: %d wrong passcodes, it stops working", invite.ID, maxPasscodeTries)
		s.Store.Drop(invite.ID)
	}
	return RejectWrongPasscode
}

// Pairing is what redeeming an invite gives: a pairing token of the inviter, for the phone to send its pair request
// with (as after scanning the inviter's QR code).
type Pairing struct {
	Inviter   string
	Token     string
	ExpiresAt time.Time
}

func (s *Service) pairing(inviter string) (Pairing, error) {
	token, expires, err := s.Book.NewToken(inviter)
	if err != nil {
		return Pairing{}, err
	}
	return Pairing{Inviter: inviter, Token: token, ExpiresAt: expires}, nil
}

// EnrollRequest redeems an invite on a phone that isn't enrolled here.
type EnrollRequest struct {
	Code        string
	Passcode    string
	Email       string
	DisplayName string
	enroll.Request
}

// Enroll redeems the invite with req.Code for a new user: checks the passcode, then the email (so the passcode is
// needed to learn whether an address has an account here), makes the user (auth.Users.AddInvited), enrolls the
// device and gives a pairing token of the inviter. The invite is used up only when all of it checked out.
func (s *Service) Enroll(clientIP string, req EnrollRequest) (enroll.Enrolled, Pairing, Rejection, error) {
	invite, rejection := s.find(clientIP, req.Code)
	if rejection != "" {
		return enroll.Enrolled{}, Pairing{}, rejection, nil
	}
	if !enroll.CheckRequest(req.Request) {
		return enroll.Enrolled{}, Pairing{}, RejectInvalidCSR, nil
	}
	if rejection := s.checkPasscode(clientIP, invite, req.Passcode); rejection != "" {
		return enroll.Enrolled{}, Pairing{}, rejection, nil
	}
	email, rejection := s.checkEmail(invite, req.Email)
	if rejection != "" {
		return enroll.Enrolled{}, Pairing{}, rejection, nil
	}
	user, err := s.Users.AddInvited(email, req.DisplayName, invite.InvitedBy, s.now())
	if errors.Is(err, auth.ErrEmailTaken) {
		return enroll.Enrolled{}, Pairing{}, RejectEmailTaken, nil
	}
	if err != nil {
		return enroll.Enrolled{}, Pairing{}, "", err
	}
	if ok, err := s.Store.Use(invite.ID, user.Name); err != nil || !ok {
		// Used by another request in the meantime: the user just made goes again.
		s.Users.Remove(user.Name)
		if err != nil {
			return enroll.Enrolled{}, Pairing{}, "", err
		}
		return enroll.Enrolled{}, Pairing{}, RejectInvalidCode, nil
	}
	s.mu.Lock()
	delete(s.wrong, invite.ID)
	s.mu.Unlock()
	enrolled, err := s.Enrollment.EnrollAs(user.Name, req.Request)
	if err != nil {
		return enroll.Enrolled{}, Pairing{}, "", err
	}
	log.Printf("Invite %s from %s used: user %s (%s) joined", invite.ID, invite.InvitedBy, user.Name, orNoEmail(email))
	pairing, err := s.pairing(invite.InvitedBy)
	if err != nil {
		// Enrolled all the same; without a token the phone asks for the inviter's QR code instead.
		log.Printf("Invite %s: no pairing token for %s: %v", invite.ID, invite.InvitedBy, err)
		pairing = Pairing{Inviter: invite.InvitedBy}
	}
	return enrolled, pairing, "", nil
}

func orNoEmail(email string) string {
	if email == "" {
		return "no email"
	}
	return email
}

// Accept redeems the invite with code for user, who is already enrolled here: gives a pairing token of the inviter.
func (s *Service) Accept(clientIP, user, code string) (Pairing, Rejection, error) {
	invite, rejection := s.find(clientIP, code)
	if rejection != "" {
		return Pairing{}, rejection, nil
	}
	if invite.InvitedBy == user {
		return Pairing{}, RejectOwnInvite, nil
	}
	if invite.Email != "" {
		if caller := s.Users.Find(user); caller != nil && caller.Email != "" && caller.Email != invite.Email {
			return Pairing{}, RejectEmailMismatch, nil
		}
	}
	if ok, err := s.Store.Use(invite.ID, user); err != nil || !ok {
		if err != nil {
			return Pairing{}, "", err
		}
		return Pairing{}, RejectInvalidCode, nil
	}
	log.Printf("Invite %s from %s used by %s, who was enrolled already", invite.ID, invite.InvitedBy, user)
	pairing, err := s.pairing(invite.InvitedBy)
	if errors.Is(err, contacts.ErrTooManyTokens) {
		return Pairing{}, RejectRateLimited, nil
	}
	return pairing, "", err
}
