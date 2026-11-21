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
