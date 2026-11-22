package auth

import "context"

type contextKey string

const (
	userContextKey     contextKey = "user"
	clientIPContextKey contextKey = "client_ip"
	serialContextKey   contextKey = "serial"
)

// WithSerial records the serial of the client certificate.
func WithSerial(ctx context.Context, serial string) context.Context {
	return context.WithValue(ctx, serialContextKey, serial)
}

// SerialFromContext is the client certificate's serial, or "" for an anonymous request.
func SerialFromContext(ctx context.Context) string {
	serial, _ := ctx.Value(serialContextKey).(string)
	return serial
}

// WithUser records the user the client certificate named.
func WithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// FromContext returns the user authenticated by client certificate, or nil for an anonymous request.
func FromContext(ctx context.Context) *User {
	user, _ := ctx.Value(userContextKey).(*User)
	return user
}

func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPContextKey, ip)
}

func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPContextKey).(string)
	return ip
}
