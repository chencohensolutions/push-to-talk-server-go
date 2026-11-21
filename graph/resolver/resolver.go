package resolver

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/model"
	"github.com/chencohensolutions/push-to-talk-server-go/invite"
	"github.com/chencohensolutions/push-to-talk-server-go/relay"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require
// here.

type Resolver struct {
	Enrollment *enroll.Service
	Users      *auth.Users
	// Who may reach whom, the prekeys and the queue (docs/messaging.md).
	Relay *relay.Relay
	// Invites (docs/authentication.md, "Invites"); nil when the config turns them off.
	Invites *invite.Service
	Now     func() time.Time
	// The server's build, shown by serverInfo.
	Version string
	// Who this server is and where, for serverInfo.discovery; nil when unknown.
	Discovery func() *model.ServerDiscovery
}

// APIVersion is serverInfo.api: raised when a change needs newer apps.
const APIVersion = 1

// caPEM is the CA that signs this server's certificates, PEM, for the apps to keep (EnrolledDevice.caCertificate,
// serverInfo.caCertificate); "" when there is no issuer.
func (r *Resolver) caPEM() string {
	if r.Enrollment == nil || r.Enrollment.Issuer == nil {
		return ""
	}
	ca, _ := r.Enrollment.Issuer.CA()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))
}

func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// device is the enrolled device whose certificate made the request; empty (number 0) for a certificate made outside
// enrollment, which only a server without "enrolled_only" takes.
func (r *Resolver) device(ctx context.Context) enroll.Device {
	serial := auth.SerialFromContext(ctx)
	if serial == "" || r.Enrollment == nil {
		return enroll.Device{}
	}
	device, _ := r.Enrollment.Registry.Find(serial)
	return device
}

// enrolledDevice is what enrollDevice and renewCertificate answer.
func (r *Resolver) enrolledDevice(enrolled enroll.Enrolled) model.EnrolledDevice {
	device := enrolled.Device
	return model.EnrolledDevice{
		User:          device.User,
		DeviceName:    device.Name,
		DeviceNumber:  device.DeviceNumber,
		Certificate:   base64.StdEncoding.EncodeToString(enrolled.Certificate),
		Serial:        device.Serial,
		ExpiresAt:     device.ExpiresAt,
		CaCertificate: nonEmpty(r.caPEM()),
	}
}

func inviteModel(i invite.Invite) *model.Invite {
	return &model.Invite{ID: i.ID, Email: nonEmpty(i.Email), CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt}
}

func pairingModel(p invite.Pairing) *model.InvitePairing {
	out := &model.InvitePairing{Inviter: p.Inviter}
	if p.Token != "" {
		out.PairingToken = &model.PairingToken{Token: p.Token, ExpiresAt: p.ExpiresAt}
	}
	return out
}
