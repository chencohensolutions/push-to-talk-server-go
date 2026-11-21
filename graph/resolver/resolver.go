package resolver

import (
	"context"
	"encoding/base64"
	"encoding/pem"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/model"
)

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require
// here.

type Resolver struct {
	Enrollment *enroll.Service
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
