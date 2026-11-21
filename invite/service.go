package invite

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/contacts"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
	"github.com/chencohensolutions/push-to-talk-server-go/mail"
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
	// The email code is wrong or expired; after a few wrong ones a new code is needed.
	RejectWrongEmailCode Rejection = "WRONG_EMAIL_CODE"
	// Too many wrong codes from this address, or too many email codes for this invite.
	RejectRateLimited Rejection = "RATE_LIMITED"
	RejectInvalidCSR  Rejection = "INVALID_CSR"
	// The inviter opened their own invite.
	RejectOwnInvite Rejection = "OWN_INVITE"
	// The email couldn't be sent.
	RejectMailFailed Rejection = "MAIL_FAILED"
	// The inviter's phone emailed the code with the invite: the server sends none.
	RejectCodeFromInviter Rejection = "CODE_FROM_INVITER"
)

// maxInviterCodeTries is how many wrong codes an invite whose code the inviter emailed takes before it stops working.
const maxInviterCodeTries = 10

// Service is the invites: the store, the email codes, and what redeeming one makes (a user, a device, a pairing token).
type Service struct {
	Store      *Store
	Users      *auth.Users
	Enrollment *enroll.Service
	Book       *contacts.Book
	Mail       mail.Sender
	// The app's name in the email ("Talk").
	AppName string
	limiter *enroll.Limiter
	now     func() time.Time

	mu    sync.Mutex
	codes map[string]*emailCode // by invite id
	wrong map[string]int        // wrong codes for an invite whose code the inviter emailed, by invite id
}

func NewService(store *Store, users *auth.Users, enrollment *enroll.Service, book *contacts.Book, sender mail.Sender, now func() time.Time) *Service {
	return &Service{Store: store, Users: users, Enrollment: enrollment, Book: book, Mail: sender, AppName: "Talk",
		limiter: enroll.NewLimiter(now), now: now, codes: map[string]*emailCode{}, wrong: map[string]int{}}
}

// Create makes an invite from by, for email when it isn't empty; then it gives the email code too, for the inviter's
// phone to email with the link.
func (s *Service) Create(by, email string) (Invite, string, string, error) {
	if email != "" {
		normalized, err := NormalizeEmail(email)
		if err != nil {
			return Invite{}, "", "", err
		}
		email = normalized
	}
	invite, code, emailCode, err := s.Store.Create(by, email)
	if err == nil {
		log.Printf("Invite %s made by %s (for %s), until %s", invite.ID, by, orAnyone(invite.Email), invite.ExpiresAt.Format(time.DateOnly))
	}
	return invite, code, emailCode, err
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
	// The inviter's phone emailed the code with the link: the friend types it, and asks the server for none.
	CodeFromInviter bool
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
		ExpiresAt: invite.ExpiresAt, CodeFromInviter: invite.EmailCodeHash != ""}, ""
}

// checkEmail is email normalized, when the invite may be redeemed with it.
func (s *Service) checkEmail(invite Invite, email string) (string, Rejection) {
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

// SendEmailCode sends a six-digit code to email, for redeeming the invite with code: a new code each time (the old
// one stops working), at most maxEmailSends per invite, resendAfter apart.
func (s *Service) SendEmailCode(clientIP, code, email string) (time.Time, Rejection) {
	invite, rejection := s.find(clientIP, code)
	if rejection != "" {
		return time.Time{}, rejection
	}
	email, rejection = s.checkEmail(invite, email)
	if rejection != "" {
		return time.Time{}, rejection
	}
	if invite.EmailCodeHash != "" {
		return time.Time{}, RejectCodeFromInviter
	}
	digits := newEmailCode()
	now := s.now()
	s.mu.Lock()
	previous := s.codes[invite.ID]
	if previous != nil && (previous.sends >= maxEmailSends || now.Sub(previous.sentAt) < resendAfter) {
		s.mu.Unlock()
		return time.Time{}, RejectRateLimited
	}
	sends := 1
	if previous != nil {
		sends = previous.sends + 1
	}
	sent := &emailCode{email: email, hash: hashCode(invite.ID + "/" + digits), expiresAt: now.Add(EmailCodeTTL),
		sentAt: now, sends: sends}
	s.codes[invite.ID] = sent
	s.mu.Unlock()

	inviter := s.Users.Find(invite.InvitedBy)
	who := invite.InvitedBy
	if inviter != nil && inviter.DisplayName != "" {
		who = inviter.DisplayName + " (" + invite.InvitedBy + ")"
	}
	subject := fmt.Sprintf("%s code: %s", s.AppName, digits)
	body := fmt.Sprintf("%s invited you to %s.\n\nYour code is %s\n\nType it in the app within %d minutes. "+
		"If you didn't ask for this, ignore this email: nothing happens without the code.\n",
		who, s.AppName, digits, int(EmailCodeTTL/time.Minute))
	if err := s.Mail.Send(email, subject, body); err != nil {
		log.Printf("Invite %s: sending the email code to %s failed: %v", invite.ID, email, err)
		s.mu.Lock()
		if s.codes[invite.ID] == sent {
			// Not sent: it doesn't count, and the phone may try again at once.
			sent.sentAt = time.Time{}
			sent.sends--
			sent.hash = ""
		}
		s.mu.Unlock()
		return time.Time{}, RejectMailFailed
	}
	log.Printf("Invite %s: email code sent to %s", invite.ID, email)
	return sent.expiresAt, ""
}

// checkEmailCode says whether digits is the code sent to email for invite; a wrong one counts against the code and
// the client's address.
func (s *Service) checkEmailCode(clientIP string, invite Invite, email, digits string) Rejection {
	digits = strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, digits)
	if invite.EmailCodeHash != "" {
		if subtle.ConstantTimeCompare([]byte(invite.EmailCodeHash), []byte(hashCode(invite.ID+"/"+digits))) == 1 {
			return ""
		}
		s.limiter.Fail(clientIP)
		s.mu.Lock()
		s.wrong[invite.ID]++
		tooMany := s.wrong[invite.ID] >= maxInviterCodeTries
		s.mu.Unlock()
		if tooMany {
			log.Printf("Invite %s: %d wrong codes, it stops working", invite.ID, maxInviterCodeTries)
			s.Store.Drop(invite.ID)
		}
		return RejectWrongEmailCode
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	sent := s.codes[invite.ID]
	if sent == nil || sent.hash == "" || sent.email != email || !now.Before(sent.expiresAt) {
		return RejectWrongEmailCode
	}
	if subtle.ConstantTimeCompare([]byte(sent.hash), []byte(hashCode(invite.ID+"/"+digits))) != 1 {
		s.limiter.Fail(clientIP)
		sent.wrong++
		if sent.wrong >= emailCodeTries {
			sent.hash = "" // ask for a new one
		}
		return RejectWrongEmailCode
	}
	return ""
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
	Email       string
	EmailCode   string
	DisplayName string
	enroll.Request
}

// Enroll redeems the invite with req.Code for a new user: checks the email and its code, makes the user (named from
// the email, auth.Users.AddInvited), enrolls the device and gives a pairing token of the inviter. The invite is used
// up only when all of it checked out.
func (s *Service) Enroll(clientIP string, req EnrollRequest) (enroll.Enrolled, Pairing, Rejection, error) {
	invite, rejection := s.find(clientIP, req.Code)
	if rejection != "" {
		return enroll.Enrolled{}, Pairing{}, rejection, nil
	}
	email, rejection := s.checkEmail(invite, req.Email)
	if rejection != "" {
		return enroll.Enrolled{}, Pairing{}, rejection, nil
	}
	if !enroll.CheckRequest(req.Request) {
		return enroll.Enrolled{}, Pairing{}, RejectInvalidCSR, nil
	}
	if rejection := s.checkEmailCode(clientIP, invite, email, req.EmailCode); rejection != "" {
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
	delete(s.codes, invite.ID)
	s.mu.Unlock()
	enrolled, err := s.Enrollment.EnrollAs(user.Name, req.Request)
	if err != nil {
		return enroll.Enrolled{}, Pairing{}, "", err
	}
	log.Printf("Invite %s from %s used: user %s (%s) joined", invite.ID, invite.InvitedBy, user.Name, email)
	pairing, err := s.pairing(invite.InvitedBy)
	if err != nil {
		// Enrolled all the same; without a token the phone asks for the inviter's QR code instead.
		log.Printf("Invite %s: no pairing token for %s: %v", invite.ID, invite.InvitedBy, err)
		pairing = Pairing{Inviter: invite.InvitedBy}
	}
	return enrolled, pairing, "", nil
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
