package resolver

import (
	"fmt"

	"github.com/vektah/gqlparser/v2/gqlerror"
)

// Codes a device acts on, sent as extensions.code of a GraphQL error. Other errors are for the log: a device shows
// them as a server problem.
const (
	// CodeUnauthorized: no client certificate was sent for a field that needs one (auth.RequireUserUnlessPublic), or
	// the certificate isn't an enrolled device's (serverInfo.deviceNumber, me).
	CodeUnauthorized = "UNAUTHORIZED"
)

// coded is an error with a code devices act on.
func coded(code, format string, args ...any) error {
	return &gqlerror.Error{Message: fmt.Sprintf(format, args...), Extensions: map[string]any{"code": code}}
}

// Codes of the keys, pairing and contacts fields (messaging.graphql).
const (
	// CodeNotEnrolled: a certificate made outside enrollment (device number 0) can't keep keys or messages.
	CodeNotEnrolled = "NOT_ENROLLED"
	// CodeInvalidKey: a key, signature, id or registration id of the wrong size or range, or not base64.
	CodeInvalidKey = "INVALID_KEY"
	// CodeMissingKeys: a device's first uploadPrekeys without its signed and last-resort Kyber prekeys.
	CodeMissingKeys = "MISSING_KEYS"
	// CodeIdentityKeyMismatch: uploadPrekeys with an identity key that isn't the user's.
	CodeIdentityKeyMismatch = "IDENTITY_KEY_MISMATCH"
	// CodeNoIdentityKey: the user has no identity key yet (prekeyBundles of a user no device uploaded keys for).
	CodeNoIdentityKey = "NO_IDENTITY_KEY"
	// CodeOtherDevicesActive: replaceIdentityKey while another device of the user still has keys.
	CodeOtherDevicesActive = "OTHER_DEVICES_ACTIVE"
	// CodeNoPairing: confirmPair with a user the caller wasn't introduced to by a pairing token.
	CodeNoPairing = "NO_PAIRING"
	// CodeRateLimited: too many pairing tokens at once.
	CodeRateLimited = "RATE_LIMITED"
)

// Codes of the invite fields (invite.graphql).
const (
	// CodeInvitesOff: the server's config.json has "invites": false.
	CodeInvitesOff = "INVITES_OFF"
	// CodeInvalidEmail: createInvite with something that isn't one plain email address.
	CodeInvalidEmail = "INVALID_EMAIL"
)

// Codes of the push and presence fields (push.graphql).
const (
	// CodeInvalidToken: registerPush with a token that can't be an FCM registration token.
	CodeInvalidToken = "INVALID_TOKEN"
)
