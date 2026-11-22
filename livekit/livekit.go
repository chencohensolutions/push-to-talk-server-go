// Package livekit is what ptt-server does with its LiveKit server (phase 5b, the live talk path): the API key and
// secret (in the key file LiveKit reads too), the room tokens it signs for phones after its own checks, the room API
// it calls to take a participant out (Twirp over HTTP, JSON), and running livekit-server beside it, started again
// when it exits. Tokens are HS256 JWTs made with the standard library, so no LiveKit SDK is linked. See
// docs/messaging.md, "Live talk".
package livekit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// TokenTTL is how long a room token a phone gets lasts.
const TokenTTL = 10 * time.Minute

// Keys is LiveKit's API key and its secret.
type Keys struct {
	Key    string
	Secret string
}

// LoadKeys reads a LiveKit key file: lines of "key: secret" (the first one is used).
func LoadKeys(path string) (Keys, error) {
	f, err := os.Open(path)
	if err != nil {
		return Keys{}, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, secret, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) != "" && len(strings.TrimSpace(secret)) >= 32 {
			return Keys{Key: strings.TrimSpace(key), Secret: strings.TrimSpace(secret)}, nil
		}
	}
	return Keys{}, fmt.Errorf("%s holds no \"key: secret\" line with a secret of 32 characters or more", path)
}

// NewKeys is a new random key and secret, as the key file's line.
func NewKeys() Keys {
	raw := make([]byte, 6)
	rand.Read(raw)
	secret := make([]byte, 32)
	rand.Read(secret)
	return Keys{Key: "API" + hex.EncodeToString(raw), Secret: base64.RawURLEncoding.EncodeToString(secret)}
}

// Grant is the "video" claim of a LiveKit token.
type Grant struct {
	Room           string `json:"room,omitempty"`
	RoomJoin       bool   `json:"roomJoin,omitempty"`
	RoomAdmin      bool   `json:"roomAdmin,omitempty"`
	RoomList       bool   `json:"roomList,omitempty"`
	RoomCreate     bool   `json:"roomCreate,omitempty"`
	CanPublish     *bool  `json:"canPublish,omitempty"`
	CanSubscribe   *bool  `json:"canSubscribe,omitempty"`
	CanPublishData *bool  `json:"canPublishData,omitempty"`
}

func yes() *bool { v := true; return &v }
func no() *bool  { v := false; return &v }

// Sign is a LiveKit access token for identity (empty for the server's own calls) with grant, valid for ttl.
func (k Keys) Sign(identity string, grant Grant, now time.Time, ttl time.Duration) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]any{"iss": k.Key, "nbf": now.Add(-time.Minute).Unix(), "exp": now.Add(ttl).Unix(), "video": grant}
	if identity != "" {
		claims["sub"] = identity
		claims["name"] = identity
	}
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := header + "." + enc.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(k.Secret))
	mac.Write([]byte(unsigned))
	return unsigned + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

// JoinToken is a phone's token for room: join, send its microphone, hear the others; no data messages (floor
// control is on ptt-server's /ws).
func (k Keys) JoinToken(identity, room string, now time.Time) (string, error) {
	return k.Sign(identity, Grant{Room: room, RoomJoin: true, CanPublish: yes(), CanSubscribe: yes(),
		CanPublishData: no()}, now, TokenTTL)
}

// Identity is a device's identity in LiveKit rooms: "user.device".
func Identity(user string, device int) string { return fmt.Sprintf("%s.%d", user, device) }

// GroupRoom and PairRoom name a conversation's room. A pair's room is a hash of the two names, so LiveKit's log
// doesn't spell out who talks to whom.
func GroupRoom(group string) string { return "g-" + group }

func PairRoom(a, b string) string {
	if a > b {
		a, b = b, a
	}
	sum := sha256.Sum256([]byte("ptt-room/v1|" + a + "|" + b))
	return "u-" + hex.EncodeToString(sum[:16])
}

// CallRoom names a call's room: each call has its own, with a fresh media key in its encrypted invite.
func CallRoom(call string) string { return "c-" + call }

// MaxCallParticipants is the most devices in one video call (the plan's first build: 8).
const MaxCallParticipants = 8

// Client calls LiveKit's room API.
type Client struct {
	Keys Keys
	// LiveKit's HTTP address, on loopback (http://127.0.0.1:7880).
	URL  string
	HTTP *http.Client
}

func (c *Client) call(ctx context.Context, method string, grant Grant, in, out any) error {
	token, err := c.Keys.Sign("", grant, time.Now(), time.Minute)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+"/twirp/livekit.RoomService/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var twirp struct{ Code, Msg string }
		json.Unmarshal(answer, &twirp)
		if twirp.Code == "not_found" {
			return ErrNotFound
		}
		return fmt.Errorf("LiveKit %s: %s %s %s", method, resp.Status, twirp.Code, twirp.Msg)
	}
	if out != nil {
		return json.Unmarshal(answer, out)
	}
	return nil
}

// ErrNotFound is LiveKit saying the room or participant isn't there (nothing to take out).
var ErrNotFound = errors.New("not in LiveKit")

// Remove takes identity out of room now. Not being there is no error.
func (c *Client) Remove(ctx context.Context, room, identity string) error {
	err := c.call(ctx, "RemoveParticipant", Grant{Room: room, RoomAdmin: true}, map[string]string{"room": room, "identity": identity}, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// CreateRoom makes room (or finds it made) with a cap on its participants and a short life once empty.
func (c *Client) CreateRoom(ctx context.Context, room string, maxParticipants int) error {
	return c.call(ctx, "CreateRoom", Grant{RoomCreate: true}, map[string]any{"name": room,
		"max_participants": maxParticipants, "empty_timeout": 60}, nil)
}

// Rooms is the names of the rooms open now.
func (c *Client) Rooms(ctx context.Context) ([]string, error) {
	var out struct {
		Rooms []struct{ Name string } `json:"rooms"`
	}
	if err := c.call(ctx, "ListRooms", Grant{RoomList: true}, map[string]any{}, &out); err != nil {
		return nil, err
	}
	var names []string
	for _, r := range out.Rooms {
		names = append(names, r.Name)
	}
	return names, nil
}

// Participants is the identities in room now.
func (c *Client) Participants(ctx context.Context, room string) ([]string, error) {
	var out struct {
		Participants []struct{ Identity string } `json:"participants"`
	}
	err := c.call(ctx, "ListParticipants", Grant{Room: room, RoomAdmin: true}, map[string]string{"room": room}, &out)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, p := range out.Participants {
		ids = append(ids, p.Identity)
	}
	return ids, nil
}

// RemoveEverywhere takes the identities that keep(identity) refuses out of every open room (a revoked device, a
// removed user). It answers how many it took out.
func (c *Client) RemoveEverywhere(ctx context.Context, gone func(identity string) bool) (int, error) {
	rooms, err := c.Rooms(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, room := range rooms {
		ids, err := c.Participants(ctx, room)
		if err != nil {
			return n, err
		}
		for _, id := range ids {
			if gone(id) {
				if err := c.Remove(ctx, room, id); err != nil {
					return n, err
				}
				n++
			}
		}
	}
	return n, nil
}

// Run keeps livekit-server (binary, with its config file) running until ctx ends, starting it again after it exits:
// at once the first time, then after a pause that grows to a minute. A value on restart stops it and starts it again
// at once (after `ptt-server livekit update` put a new program there). The keys go to it in LIVEKIT_KEYS, not through
// key_file: on Windows LiveKit refuses any key file, since Go reports every file there as readable by others.
func Run(ctx context.Context, binary, configFile string, keys Keys, restart <-chan struct{}) {
	wait := time.Second
	for {
		started := time.Now()
		once, stop := context.WithCancel(ctx)
		restarted := make(chan bool, 1)
		go func() {
			select {
			case <-restart:
				restarted <- true
				stop()
			case <-once.Done():
				restarted <- false
			}
		}()
		cmd := exec.CommandContext(once, binary, "--config", configFile)
		cmd.Stdout = logWriter{}
		cmd.Stderr = logWriter{}
		cmd.Env = append(os.Environ(), "LIVEKIT_KEYS="+keys.Key+": "+keys.Secret)
		log.Printf("LiveKit: starting %s --config %s", binary, configFile)
		err := cmd.Run()
		stop()
		if ctx.Err() != nil {
			return
		}
		if <-restarted {
			log.Printf("LiveKit: restarting (a new program)")
			wait = time.Second
			continue
		}
		log.Printf("LiveKit: exited: %v", err)
		if time.Since(started) > 5*time.Minute {
			wait = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-restart:
			log.Printf("LiveKit: restarting (a new program)")
			wait = time.Second
			continue
		case <-time.After(wait):
		}
		wait = min(2*wait, time.Minute)
	}
}

// logWriter puts LiveKit's output in the server's log, line by line.
type logWriter struct{}

func (logWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line != "" {
			log.Printf("LiveKit: %s", line)
		}
	}
	return len(p), nil
}

// ConfigYAML is the livekit.yaml setup writes: signalling on loopback only (phones reach it through ptt-server's
// /rtc), media on TCP 7881 and UDP 7882, the public IP found by STUN. It holds no keys: ptt-server passes them in
// LIVEKIT_KEYS when it starts LiveKit (see Run).
func ConfigYAML(httpPort, tcpPort, udpPort int) string {
	return fmt.Sprintf(`# LiveKit's config, written by ptt-server setup (docs/install.md, "LiveKit").
# Phones reach signalling only through ptt-server's /rtc (mTLS); media comes straight here.
# The API key and secret aren't here: ptt-server passes livekit.keys to LiveKit in LIVEKIT_KEYS.
port: %d
bind_addresses:
  - 127.0.0.1
rtc:
  tcp_port: %d
  udp_port: %d
  use_external_ip: true
logging:
  level: info
`, httpPort, tcpPort, udpPort)
}
