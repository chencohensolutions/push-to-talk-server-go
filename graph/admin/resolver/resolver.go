package resolver

import (
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/apprelease"
	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
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
	// AppReleases follows the app's releases (checkAppRelease); nil when app_releases is "none".
	AppReleases *apprelease.Watcher
}

func (r *Resolver) revoked(user string) {
	if r.Revoked != nil {
		r.Revoked(user)
	}
}
