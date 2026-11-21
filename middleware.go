package main

import (
	"log"
	"net"
	"net/http"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
)

// identify attaches the client IP and, when the client presented a certificate, its user and device. Requests
// without a certificate pass through anonymously only when allowAnonymous is set; a certificate whose user isn't in
// users.json, or that is revoked (or, with "enrolled_only", isn't in the registry), is always rejected.
func identify(config auth.AppConfig, users *auth.Users, registry *enroll.Registry, allowAnonymous bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		ctx := auth.WithClientIP(r.Context(), ip)

		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			if !allowAnonymous {
				log.Printf("Client connection rejected: no client certificate from %s", r.RemoteAddr)
				http.Error(w, "client certificate required", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		clientCert := r.TLS.PeerCertificates[0]
		commonName := clientCert.Subject.CommonName
		currentUser := users.Find(commonName)
		if currentUser == nil {
			log.Printf("Failed login: unknown client (cert CN '%s') from %s", commonName, r.RemoteAddr)
			http.Error(w, "unauthorized client certificate", http.StatusUnauthorized)
			return
		}
		serial := enroll.SerialString(clientCert.SerialNumber)
		if registry.IsRevoked(serial) {
			log.Printf("Failed login: revoked certificate %s (user %s) from %s", serial, currentUser.Name, r.RemoteAddr)
			http.Error(w, "client certificate revoked", http.StatusUnauthorized)
			return
		}
		ctx = auth.WithSerial(ctx, serial)
		device, enrolled := registry.Find(serial)
		if !enrolled && config.EnrolledOnly {
			log.Printf("Failed login: certificate %s (user %s) from %s isn't in the device registry", serial, currentUser.Name, r.RemoteAddr)
			http.Error(w, "client certificate not enrolled", http.StatusUnauthorized)
			return
		}
		if enrolled && device.User != currentUser.Name {
			// Enrollment signs CN=<the code's user>, so this is a registry edited by hand.
			log.Printf("Failed login: certificate %s names %s, the registry %s", serial, currentUser.Name, device.User)
			http.Error(w, "unauthorized client certificate", http.StatusUnauthorized)
			return
		}
		if enrolled && device.RenewedFrom != "" {
			if old, err := registry.UseRenewal(serial, time.Now().UTC()); err != nil {
				log.Printf("Renewed certificate %s in use, but %s couldn't be revoked: %v", serial, device.RenewedFrom, err)
			} else if old != "" {
				log.Printf("Renewed certificate %s of %q in use: %s revoked", serial, device.Name, old)
			}
		}
		log.Printf("Client connected: user=%s device=%d from %s (%s %s)", currentUser.Name, device.DeviceNumber,
			r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r.WithContext(auth.WithUser(ctx, currentUser)))
	})
}

// limitBody bounds a request's body: anonymous bytes from a client without a certificate, known from a device.
// Reading past it fails, and the handler answers an error.
func limitBody(anonymous, known int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := anonymous
		if auth.FromContext(r.Context()) != nil {
			limit = known
		}
		if r.ContentLength > limit {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// withDeadlines bounds how long one request may take to arrive and to be answered.
func withDeadlines(read, write time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		rc.SetReadDeadline(time.Now().Add(read))
		rc.SetWriteDeadline(time.Now().Add(write))
		next.ServeHTTP(w, r)
	})
}

// loggingListener logs every connection as it is accepted, before TLS: a client whose certificate the
// handshake rejects still shows up here.
type loggingListener struct {
	net.Listener
}

func (l *loggingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	log.Printf("Client attempting to connect from %s", conn.RemoteAddr())
	return conn, nil
}
