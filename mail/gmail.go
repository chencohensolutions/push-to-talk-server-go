package mail

// Sending through Gmail's API with a send-only grant, so the server keeps no mail password (2026-11-22: hen wanted
// the invite codes sent from his own address without storing its password). `ptt-server mail-login` signs in once
// in a browser and keeps a refresh token for the gmail.send scope, which can send mail and can't read any; the owner
// revokes it in the Google account (Security, Third-party access) at any time.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// GmailConfig is config.json's "gmail": send through the Gmail API as the account mail-login signed in with.
type GmailConfig struct {
	// The OAuth client downloaded from Google Cloud (Credentials, OAuth client ID, type "Desktop app").
	ClientFile string `json:"client_file"`
	// Where mail-login keeps the account and its send-only refresh token (default gmail.token).
	TokenFile string `json:"token_file"`
	// The name shown beside the address, e.g. "Talk"; none when empty.
	FromName string `json:"from_name"`
}

// DefaultGmailTokenFile is where mail-login writes the token when the config names none.
const DefaultGmailTokenFile = "gmail.token"

// The scopes mail-login asks for: sending only, and the address (openid email) so the From line needs no setting.
const gmailScopes = "https://www.googleapis.com/auth/gmail.send openid email"

// Google's endpoints; tests point them at a fake.
var (
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL = "https://oauth2.googleapis.com/token"
	gmailSendURL   = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
)

type oauthClient struct {
	ID     string `json:"client_id"`
	Secret string `json:"client_secret"`
}

// readClient reads the client file Google Cloud gives for a desktop app ({"installed": {...}}), or a web one.
func readClient(path string) (oauthClient, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return oauthClient{}, fmt.Errorf("gmail.client_file: %w", err)
	}
	var file struct {
		Installed *oauthClient `json:"installed"`
		Web       *oauthClient `json:"web"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return oauthClient{}, fmt.Errorf("gmail.client_file: %w", err)
	}
	client := file.Installed
	if client == nil {
		client = file.Web
	}
	if client == nil || client.ID == "" {
		return oauthClient{}, errors.New("gmail.client_file: no client_id (download the JSON of a Desktop app OAuth client)")
	}
	return *client, nil
}

// gmailToken is the token file: the account and its refresh token.
type gmailToken struct {
	Email        string `json:"email"`
	RefreshToken string `json:"refresh_token"`
}

func readToken(path string) (gmailToken, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return gmailToken{}, fmt.Errorf("%s is missing: run `ptt-server mail-login` first", path)
		}
		return gmailToken{}, err
	}
	var t gmailToken
	if err := json.Unmarshal(data, &t); err != nil || t.RefreshToken == "" || t.Email == "" {
		return gmailToken{}, fmt.Errorf("%s is not a token mail-login wrote: run `ptt-server mail-login` again", path)
	}
	return t, nil
}

// writePrivate writes data through a temp file and a rename, readable by the owner only.
func writePrivate(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	// Windows has no Unix modes (the folder's ACL protects the file there), so a failure is ignored.
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Gmail sends through the Gmail API.
type Gmail struct {
	client   oauthClient
	token    gmailToken
	fromName string
	http     *http.Client

	mu          sync.Mutex
	accessToken string
	expires     time.Time
}

// NewGmail reads the client and the token mail-login wrote.
func NewGmail(config GmailConfig) (*Gmail, error) {
	client, err := readClient(config.ClientFile)
	if err != nil {
		return nil, err
	}
	tokenFile := config.TokenFile
	if tokenFile == "" {
		tokenFile = DefaultGmailTokenFile
	}
	token, err := readToken(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("gmail: %w", err)
	}
	return &Gmail{client: client, token: token, fromName: config.FromName, http: &http.Client{Timeout: smtpTimeout}}, nil
}

// From is the address the mail comes from.
func (g *Gmail) From() string { return g.token.Email }

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

func postToken(client *http.Client, form url.Values) (tokenResponse, error) {
	resp, err := client.PostForm(googleTokenURL, form)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()
	var t tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t); err != nil {
		return tokenResponse{}, fmt.Errorf("Google's token answer (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || t.Error != "" {
		if t.Error == "invalid_grant" {
			return t, errors.New("Google refused the saved sign-in (revoked or expired): run `ptt-server mail-login` again")
		}
		return t, fmt.Errorf("Google's token endpoint: HTTP %d %s %s", resp.StatusCode, t.Error, t.Description)
	}
	return t, nil
}

// access is a current access token, refreshed a minute before it expires.
func (g *Gmail) access() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.accessToken != "" && time.Now().Before(g.expires.Add(-time.Minute)) {
		return g.accessToken, nil
	}
	t, err := postToken(g.http, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {g.token.RefreshToken},
		"client_id":     {g.client.ID},
		"client_secret": {g.client.Secret},
	})
	if err != nil {
		return "", err
	}
	g.accessToken = t.AccessToken
	g.expires = time.Now().Add(time.Duration(t.ExpiresIn) * time.Second)
	return g.accessToken, nil
}

func (g *Gmail) Send(to, subject, body string) error {
	token, err := g.access()
	if err != nil {
		return err
	}
	from := (&mail.Address{Name: g.fromName, Address: g.token.Email}).String()
	message := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + mimeHeader(subject) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n")
	payload, _ := json.Marshal(map[string]string{"raw": base64.RawURLEncoding.EncodeToString([]byte(message))})
	req, err := http.NewRequest(http.MethodPost, gmailSendURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Gmail API: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(detail)))
	}
	return nil
}

// Login signs in to Google once in a browser (the loopback flow for desktop apps, with PKCE) and writes the
// account and its send-only refresh token to config.TokenFile. open shows the sign-in page (a browser, or a line
// to copy); it gets the URL.
func Login(ctx context.Context, config GmailConfig, open func(string)) (string, error) {
	client, err := readClient(config.ClientFile)
	if err != nil {
		return "", err
	}
	tokenFile := config.TokenFile
	if tokenFile == "" {
		tokenFile = DefaultGmailTokenFile
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer listener.Close()
	redirect := "http://" + listener.Addr().String() + "/"
	state, verifier := randomString(), randomString()
	challenge := sha256.Sum256([]byte(verifier))
	authURL := googleAuthURL + "?" + url.Values{
		"client_id":             {client.ID},
		"redirect_uri":          {redirect},
		"response_type":         {"code"},
		"scope":                 {gmailScopes},
		"access_type":           {"offline"},
		"prompt":                {"consent"},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}.Encode()

	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/" || q.Get("state") != state {
			http.NotFound(w, r)
			return
		}
		if e := q.Get("error"); e != "" {
			fmt.Fprintln(w, "Sign-in was cancelled. You can close this tab.")
			done <- result{err: fmt.Errorf("Google answered %s", e)}
			return
		}
		fmt.Fprintln(w, "Signed in. ptt-server can now send its invite codes. You can close this tab.")
		done <- result{code: q.Get("code")}
	})}
	go server.Serve(listener)
	defer server.Close()
	open(authURL)

	var got result
	select {
	case got = <-done:
	case <-ctx.Done():
		return "", errors.New("no sign-in within the time allowed")
	}
	if got.err != nil {
		return "", got.err
	}
	t, err := postToken(&http.Client{Timeout: smtpTimeout}, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {got.code},
		"redirect_uri":  {redirect},
		"client_id":     {client.ID},
		"client_secret": {client.Secret},
		"code_verifier": {verifier},
	})
	if err != nil {
		return "", err
	}
	if t.RefreshToken == "" {
		return "", errors.New("Google gave no refresh token: remove ptt-server's access in your Google account and run mail-login again")
	}
	email, err := idTokenEmail(t.IDToken)
	if err != nil {
		return "", err
	}
	data, _ := json.MarshalIndent(gmailToken{Email: email, RefreshToken: t.RefreshToken}, "", "  ")
	if err := writePrivate(tokenFile, append(data, '\n')); err != nil {
		return "", err
	}
	return email, nil
}

// idTokenEmail reads the verified address from the id token. It came straight from Google's token endpoint over
// TLS, so its signature isn't checked again.
func idTokenEmail(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", errors.New("Google gave no id token (the openid email scope is needed)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("the id token: %w", err)
	}
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("the id token: %w", err)
	}
	if claims.Email == "" || !claims.Verified {
		return "", errors.New("Google gave no verified address for this account")
	}
	return strings.ToLower(claims.Email), nil
}

func randomString() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
