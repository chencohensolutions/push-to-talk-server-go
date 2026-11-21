package resolver

import (
	"time"

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
}
