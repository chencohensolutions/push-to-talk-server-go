package resolver

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/graph/model"
	"github.com/chencohensolutions/push-to-talk-server-go/relay"
	"github.com/chencohensolutions/push-to-talk-server-go/store"
)

// caller is the user and the enrolled device that made the request; NOT_ENROLLED for a certificate made outside
// enrollment.
func (r *Resolver) caller(ctx context.Context) (store.Device, error) {
	user := auth.FromContext(ctx)
	if user == nil {
		return store.Device{}, coded(CodeUnauthorized, "client certificate required")
	}
	device := r.device(ctx)
	if device.DeviceNumber == 0 {
		return store.Device{}, coded(CodeNotEnrolled, "this certificate wasn't issued by enrollment: enroll the device")
	}
	return store.Device{User: user.Name, Number: device.DeviceNumber}, nil
}

var b64 = base64.StdEncoding

func encode(b []byte) string { return b64.EncodeToString(b) }

func encodeOrNil(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := encode(b)
	return &s
}

// keyDecoder decodes and checks the keys of one request, keeping the first problem.
type keyDecoder struct{ err error }

func (k *keyDecoder) bytes(what, text string, check func(string, []byte) error) []byte {
	if k.err != nil {
		return nil
	}
	b, err := b64.DecodeString(text)
	if err != nil {
		k.err = coded(CodeInvalidKey, "%s isn't base64", what)
		return nil
	}
	if err := check(what, b); err != nil {
		k.err = coded(CodeInvalidKey, "%v", err)
	}
	return b
}

func (k *keyDecoder) id(what string, id int) int {
	if k.err == nil {
		if err := relay.CheckKeyID(what, id); err != nil {
			k.err = coded(CodeInvalidKey, "%v", err)
		}
	}
	return id
}

func (k *keyDecoder) ec(what string, in *model.PrekeyInput) store.SignedKey {
	return store.SignedKey{ID: k.id(what, in.KeyID), Public: k.bytes(what, in.PublicKey, relay.CheckECKey)}
}

func (k *keyDecoder) signed(what string, in *model.SignedPrekeyInput, check func(string, []byte) error) *store.SignedKey {
	if in == nil {
		return nil
	}
	return &store.SignedKey{ID: k.id(what, in.KeyID), Public: k.bytes(what, in.PublicKey, check),
		Signature: k.bytes(what, in.Signature, relay.CheckSignature)}
}

// refusal is a relay refusal as a GraphQL error with its code.
func refusal(err error) error {
	var refused relay.Refusal
	if errors.As(err, &refused) {
		return coded(string(refused), "%v", refused)
	}
	return err
}

func (r *Resolver) prekeyCount(d store.Device) (*model.PrekeyCount, error) {
	ec, kyber, err := r.Relay.Store.Counts(d)
	if err != nil {
		return nil, err
	}
	return &model.PrekeyCount{OneTimePrekeys: ec, OneTimeKyberPrekeys: kyber, RefillBelow: relay.RefillBelow}, nil
}

const (
	// maxPushToken is the longest FCM registration token registerPush takes (they are about 160 characters).
	maxPushToken = 4096
	// maxPresenceUsers is the most users one presence query answers for.
	maxPresenceUsers = 500
)
