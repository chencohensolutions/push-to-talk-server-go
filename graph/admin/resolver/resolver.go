package resolver

import (
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/apprelease"
	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/admin/model"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require
// here.

type Resolver struct {
	Config     auth.AppConfig
	UserStore  *auth.Users
	Enrollment *enroll.Service
	Now        func() time.Time
	// Revoked is called after a device of user was revoked, or user removed, so it takes effect at once: its /ws
	// connections close and its keys and queue go (relay.Relay.Revoked). Nil does nothing.
	Revoked func(user string)
	// LiveKitRestart restarts the livekit-server this server runs, and says whether it runs one. Nil: none.
	LiveKitRestart func() bool
	// MailEnrollment mails user an enrollment link with code (config.json "gmail"); nil when the server can't send mail.
	MailEnrollment func(user auth.User, code string, expiresAt time.Time) error
	// AppReleases follows the app's releases (checkAppRelease); nil when app_releases is "none".
	AppReleases *apprelease.Watcher
}

func (r *Resolver) revoked(user string) {
	if r.Revoked != nil {
		r.Revoked(user)
	}
}

// activeDevices is how many devices of each user aren't revoked.
func (r *Resolver) activeDevices() map[string]int {
	active := map[string]int{}
	for _, d := range r.Enrollment.Registry.List("") {
		if !r.Enrollment.Registry.IsRevoked(d.Serial) {
			active[d.User]++
		}
	}
	return active
}

func userModel(u auth.User, devices int) *model.User {
	user := &model.User{Name: u.Name, AddedAt: u.AddedAt, Devices: devices}
	if u.Email != "" {
		user.Email = &u.Email
	}
	return user
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
