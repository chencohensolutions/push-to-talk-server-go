package push

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultEndpoint is FCM's HTTP v1 API.
	DefaultEndpoint = "https://fcm.googleapis.com"
	// defaultTokenURI is Google's OAuth 2.0 token endpoint, used when the service account names none.
	defaultTokenURI = "https://oauth2.googleapis.com/token"
	// scope is the OAuth scope that lets a service account send FCM messages, and nothing else.
	scope = "https://www.googleapis.com/auth/firebase.messaging"
)

// ServiceAccount is the part of a Google service-account key file the server uses.
type ServiceAccount struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

// FCM sends messages through FCM's HTTP v1 API, signed in as a service account: the OAuth 2.0 JWT bearer flow
// (RFC 7523), with a JWT signed RS256 by the account's key, traded for an access token kept until shortly before it
// expires. Standard library only.
type FCM struct {
	account  ServiceAccount
	key      *rsa.PrivateKey
	project  string
	endpoint string
	HTTP     *http.Client
	Now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// LoadFCM reads the service-account key file at path. project overrides the file's project_id and endpoint FCM's
// address (both may be "").
func LoadFCM(path, project, endpoint string) (*FCM, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var account ServiceAccount
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if account.Type != "" && account.Type != "service_account" {
		return nil, fmt.Errorf("%s is a %q key, not a service account's", path, account.Type)
	}
	if account.ClientEmail == "" || account.PrivateKey == "" {
		return nil, fmt.Errorf("%s has no client_email or private_key: download the key from Firebase › Project settings › Service accounts", path)
	}
	key, err := parseRSAKey(account.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if project == "" {
		project = account.ProjectID
	}
	if project == "" {
		return nil, fmt.Errorf("%s has no project_id: set fcm.project_id in config.json", path)
	}
	if account.TokenURI == "" {
		account.TokenURI = defaultTokenURI
	}
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	return &FCM{account: account, key: key, project: project, endpoint: strings.TrimSuffix(endpoint, "/"),
		HTTP: &http.Client{Timeout: 30 * time.Second}, Now: time.Now}, nil
}

// Project is the Firebase project the messages are sent for.
func (f *FCM) Project() string { return f.project }

func parseRSAKey(text string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("private_key isn't PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaKey, ok := key.(*rsa.PrivateKey); ok {
			return rsaKey, nil
		}
		return nil, errors.New("private_key isn't an RSA key")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("private_key isn't an RSA key in PKCS #8 or PKCS #1")
	}
	return key, nil
}

// Wake is one push: the kind of wake-up (the only data it carries) and how FCM treats it.
type Wake struct {
	Kind string
	// High priority ("HIGH") or normal ("NORMAL").
	High bool
	// How long FCM keeps the message for a device that is offline; 0 is FCM's default (4 weeks).
	TTL time.Duration
}

// ErrUnregistered is a token FCM answered as gone: the app was uninstalled, or the token is for another project or
// isn't one. The token should be dropped.
var ErrUnregistered = errors.New("the FCM token is no longer valid")

// RetryError is a failure worth trying again later (429, 5xx, the network).
type RetryError struct{ Err error }

func (e RetryError) Error() string { return e.Err.Error() }
func (e RetryError) Unwrap() error { return e.Err }

// Send sends m to the device with token.
func (f *FCM) Send(ctx context.Context, token string, m Wake) error {
	access, err := f.accessToken(ctx)
	if err != nil {
		return err
	}
	android := map[string]any{"collapse_key": m.Kind, "priority": "NORMAL"}
	if m.High {
		android["priority"] = "HIGH"
	}
	if m.TTL > 0 {
		android["ttl"] = fmt.Sprintf("%ds", int(m.TTL/time.Second))
	}
	body, _ := json.Marshal(map[string]any{"message": map[string]any{
		"token":   token,
		"data":    map[string]string{"kind": m.Kind},
		"android": android,
	}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		f.endpoint+"/v1/projects/"+url.PathEscape(f.project)+"/messages:send", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return RetryError{err}
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	code := fcmErrorCode(answer)
	switch {
	case resp.StatusCode == http.StatusNotFound || code == "UNREGISTERED" || code == "SENDER_ID_MISMATCH":
		return fmt.Errorf("%w (%d %s)", ErrUnregistered, resp.StatusCode, code)
	case resp.StatusCode == http.StatusUnauthorized:
		// The access token was refused: sign in again next time.
		f.mu.Lock()
		f.token = ""
		f.mu.Unlock()
		return RetryError{fmt.Errorf("FCM: %d %s", resp.StatusCode, code)}
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return RetryError{fmt.Errorf("FCM: %d %s", resp.StatusCode, code)}
	}
	return fmt.Errorf("FCM: %d %s: %s", resp.StatusCode, code, strings.TrimSpace(string(answer)))
}

// fcmErrorCode is the FcmError errorCode of an error answer (UNREGISTERED, SENDER_ID_MISMATCH, …), or its status.
func fcmErrorCode(answer []byte) string {
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				Type      string `json:"@type"`
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(answer, &e) != nil {
		return ""
	}
	for _, d := range e.Error.Details {
		if d.ErrorCode != "" {
			return d.ErrorCode
		}
	}
	return e.Error.Status
}

// accessToken is an OAuth access token for the service account, from the cache while it has a minute left.
func (f *FCM) accessToken(ctx context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.Now()
	if f.token != "" && now.Add(time.Minute).Before(f.expires) {
		return f.token, nil
	}
	assertion, err := f.assertion(now)
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.account.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return "", RetryError{fmt.Errorf("signing in to Google: %w", err)}
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("signing in to Google as %s: %d %s", f.account.ClientEmail, resp.StatusCode, strings.TrimSpace(string(answer)))
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return "", RetryError{err}
		}
		return "", err
	}
	var got struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(answer, &got); err != nil || got.AccessToken == "" {
		return "", fmt.Errorf("signing in to Google: no access token in the answer")
	}
	if got.ExpiresIn <= 0 {
		got.ExpiresIn = 3600
	}
	f.token, f.expires = got.AccessToken, now.Add(time.Duration(got.ExpiresIn)*time.Second)
	return f.token, nil
}

// assertion is the signed JWT the token endpoint takes: the service account asks for the FCM scope for an hour.
func (f *FCM) assertion(now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": f.account.PrivateKeyID})
	claims, _ := json.Marshal(map[string]any{
		"iss":   f.account.ClientEmail,
		"scope": scope,
		"aud":   f.account.TokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(signature), nil
}
