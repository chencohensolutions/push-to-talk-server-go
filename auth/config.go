// Package auth holds the server's configuration, its users (users.json) and the identity of a request: the user
// and device that the client certificate named. See docs/authentication.md.
package auth

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/chencohensolutions/push-to-talk-server-go/mail"
)

type AppConfig struct {
	TLSCert  string `json:"tls_cert"`
	TLSKey   string `json:"tls_key"`
	ClientCA string `json:"client_ca"`
	// Private key of ClientCA; signs the certificates issued to enrolled devices.
	ClientCAKey string `json:"client_ca_key"`
	// Address devices use to reach the server (e.g. https://192.168.50.2:56400); printed by enroll-code.
	PublicURL string `json:"public_url"`
	// Port devices connect to (default 56400); a test server beside the real one uses another.
	Port string `json:"port"`
	// Publish this server's addresses in the BitTorrent DHT, so phones find it after its address changes
	// (docs/discovery.md). On unless set to false.
	Discovery *bool `json:"discovery"`
	// Ask the home router to forward Port to this machine (UPnP IGD or NAT-PMP), renewed while the server runs and
	// removed when it stops (docs/discovery.md, "Opening the router"). On unless set to false.
	PortMapping *bool `json:"port_mapping"`
	// Serve the GraphQL playground page on "/" (for development). Off unless set.
	Playground bool `json:"playground"`
	// The users (default users.json), written by `ptt-server user add` and `user remove`.
	UsersFile string `json:"users_file"`
	// Registry of enrolled devices (default devices.json).
	DevicesFile string `json:"devices_file"`
	// Take only certificates the registry lists (enrolled with a code): one the CA signed that it doesn't know is
	// refused. Setup turns it on.
	EnrolledOnly bool `json:"enrolled_only"`
	// Pairs and blocks (default pairs.json): who may send to whom (docs/messaging.md).
	PairsFile string `json:"pairs_file"`
	// Who is in which group (default groups.json): routing for group messages (docs/messaging.md, "Groups").
	GroupsFile string `json:"groups_file"`
	// The SQLite database (default ptt.db): the devices' public prekeys and the message queue.
	DatabaseFile string `json:"database_file"`
	// The folder of clips and attachments, ciphertext only (default blobs).
	BlobDir string `json:"blob_dir"`
	// Days a clip or attachment is kept (default 30).
	BlobDays int `json:"blob_days"`
	// The largest file a phone may upload, in MB (default 20480): a shared video's original can be gigabytes.
	MaxBlobMB int64 `json:"max_blob_mb"`
	// Days a shared original (a picture's, video's or file's, uploaded when someone asked for it) is kept, encrypted
	// (default 30; 2026-11-28, hen), so whoever asks again gets it without waking the sender's phone.
	MediaDays int `json:"media_days"`
	// The most days a phone may ask shared media be kept (default 730; 2026-11-28, hen: "the client can make the
	// server keep it for one year or something"); its Settings › Storage chooses 30 days, 1 year or 2 years.
	MediaMaxDays int `json:"media_max_days"`
	// How much each user's media kept longer than media_days may take, in GB (default 200); past it their oldest fall
	// back to media_days. -1: no bound.
	MediaQuotaGB int64 `json:"media_quota_gb"`
	// The space, in GB, a file upload must leave free on the blobs folder's disk (default 10); an upload that would
	// leave less is refused 507, so kept originals never fill the server's disk. 0 is the default; -1 doesn't check.
	MinFreeGB int64 `json:"min_free_gb"`
	// Days an envelope waits in the queue for a device that doesn't take it (default 30).
	QueueDays int `json:"queue_days"`
	// Let enrolled users invite friends (createInvite): one link and its passcode, sent from the inviter's phone,
	// that enroll the friend and pair them with whoever invited them (docs/authentication.md, "Invites"). On unless
	// set to false.
	Invites *bool `json:"invites"`
	// The invites waiting to be used (default invites.json).
	InvitesFile string `json:"invites_file"`
	// Send enrollment links by email through the Gmail API, with the send-only grant `ptt-server mail-login` keeps
	// (docs/install.md, "Email"). With it, devices enroll only by a link mailed to their user's address
	// (docs/authentication.md, "Enrollment by email"); without it, by codes the admin prints.
	Gmail *mail.GmailConfig `json:"gmail,omitempty"`
	// No longer used: until 2026-11-22 the server could send mail over SMTP, with a password in a file. Taken and
	// ignored, so an old config.json still starts the server (UnusedKeys says so in the log).
	SMTP json.RawMessage `json:"smtp,omitempty"`
	// Waking phones through Firebase Cloud Messaging (docs/messaging.md, "Push"). Without it the server sends no
	// pushes: phones receive only while connected.
	FCM *FCMConfig `json:"fcm,omitempty"`
	// The live talk path (phase 5b): a LiveKit server beside this one (docs/install.md, "LiveKit"). Without it,
	// talkToken answers LIVE_OFF and talk goes by the clip path only.
	LiveKit *LiveKitConfig `json:"livekit,omitempty"`
	// The GitHub repository (owner/name) the Talk app is released from, followed hourly so phones are pushed an
	// "app_update" when a new release is out (docs/install.md, "App updates"). Default
	// chencohensolutions/push-to-talk-kmp; "none" turns it off.
	AppReleases string `json:"app_releases,omitempty"`
	// The latest app release seen (default app-release.json).
	AppReleaseFile string `json:"app_release_file,omitempty"`
	// Loopback-only listener for the admin GraphQL API (default 127.0.0.1:8082).
	AdminAddr string `json:"admin_addr"`
	// Token for the admin API, rewritten on every server start (default admin.token).
	AdminTokenFile string `json:"admin_token_file"`
}

// LiveKitConfig is where the LiveKit server is and how ptt-server runs it. Every field has a default.
type LiveKitConfig struct {
	// livekit-server's program: ptt-server starts it and starts it again when it exits. "" (the default) runs
	// livekit-server(.exe) from beside ptt-server when it is there; "none" runs nothing (LiveKit runs on its own).
	Binary string `json:"binary,omitempty"`
	// LiveKit's own config (default livekit.yaml), which setup writes.
	ConfigFile string `json:"config_file,omitempty"`
	// The API key and secret, "key: secret" (default livekit.keys); setup makes it. A secret.
	KeysFile string `json:"keys_file,omitempty"`
	// LiveKit's signalling, on loopback (default http://127.0.0.1:7880): /rtc is passed to it, and the room API.
	URL string `json:"url,omitempty"`
	// The media ports LiveKit listens on, mapped on the router with the same number (defaults 7881 and 7882).
	TCPPort int `json:"tcp_port,omitempty"`
	UDPPort int `json:"udp_port,omitempty"`
	// The most devices in one call's room (default 32). Each device in a video call receives every other camera, so
	// the server's upload grows with the square of this; phones subscribe to a small layer for small tiles.
	MaxCallDevices int `json:"max_call_devices,omitempty"`
	// Whether the server may keep calls' streams, still encrypted end to end, while someone in the call records it
	// (recordCall; default true; 2026-11-22, hen).
	KeepCalls *bool `json:"keep_calls,omitempty"`
	// Days a kept call's streams are held after its recording starts; the hourly sweep then deletes them
	// (default 7; 2026-11-23, hen).
	KeepCallDays int `json:"keep_call_days,omitempty"`
	// Hours a push kept for members who weren't in its talk room is held when not all of them read it (default 24;
	// 2026-11-25, hen: the talk buffer).
	TalkBufferHours int `json:"talk_buffer_hours,omitempty"`
}

// KeepsCalls says whether the server keeps calls that someone records (livekit.keep_calls, default on).
func (l LiveKitConfig) KeepsCalls() bool { return l.KeepCalls == nil || *l.KeepCalls }

// DefaultMaxCallDevices is livekit.max_call_devices when config.json doesn't say: 32 (2026-11-22, hen; it was 8).
const DefaultMaxCallDevices = 32

// DefaultTalkBufferHours is livekit.talk_buffer_hours when config.json doesn't say.
const DefaultTalkBufferHours = 24

// DefaultKeepCallDays is livekit.keep_call_days when config.json doesn't say: a kept call is deleted a week after
// its recording starts (2026-11-23, hen).
const DefaultKeepCallDays = 7

// LiveKitOn says whether the live talk path is set up ("livekit" in config.json).
func (c AppConfig) LiveKitOn() bool { return c.LiveKit != nil }

// FCMConfig is how the server reaches FCM's HTTP v1 API (docs/install.md, "Push").
type FCMConfig struct {
	// The Firebase project's service-account key, JSON, as the Firebase console downloads it (Project settings ›
	// Service accounts › Generate new private key). A secret: it can send pushes to every phone of the app.
	ServiceAccountFile string `json:"service_account_file"`
	// The Firebase project id; default the service account's project_id.
	ProjectID string `json:"project_id,omitempty"`
	// FCM's address, default https://fcm.googleapis.com; another one for tests.
	Endpoint string `json:"endpoint,omitempty"`
}

const (
	DefaultPort           = "56400"
	DefaultUsersFile      = "users.json"
	DefaultDevicesFile    = "devices.json"
	DefaultPairsFile      = "pairs.json"
	DefaultGroupsFile     = "groups.json"
	DefaultInvitesFile    = "invites.json"
	DefaultDatabaseFile   = "ptt.db"
	DefaultQueueDays      = 30
	DefaultBlobDir        = "blobs"
	DefaultBlobDays       = 30
	DefaultMaxBlobMB      = 20480
	DefaultMediaDays      = 30
	DefaultMediaMaxDays   = 730
	DefaultMediaQuotaGB   = 200
	DefaultMinFreeGB      = 10
	DefaultAdminAddr      = "127.0.0.1:8082"
	DefaultAppReleases    = "chencohensolutions/push-to-talk-kmp"
	DefaultAppReleaseFile = "app-release.json"
	DefaultAdminTokenFile = "admin.token"
)

// DiscoveryOn says whether the server uses the DHT: on unless config.json sets "discovery": false.
func (c AppConfig) DiscoveryOn() bool { return c.Discovery == nil || *c.Discovery }

// InvitesOn says whether users may invite friends: on unless "invites": false.
func (c AppConfig) InvitesOn() bool { return c.Invites == nil || *c.Invites }

// AppReleasesOn says whether the server follows the app's releases: on unless app_releases is "none".
func (c AppConfig) AppReleasesOn() bool { return c.AppReleases != "none" }

// PushOn says whether config.json names an FCM service account.
func (c AppConfig) PushOn() bool { return c.FCM != nil && c.FCM.ServiceAccountFile != "" }

// PortMappingOn says whether the server asks the router to forward its port: on unless "port_mapping": false.
func (c AppConfig) PortMappingOn() bool { return c.PortMapping == nil || *c.PortMapping }

// UnusedKeys are the keys config.json has that the server no longer uses ("smtp"), to say so in the log.
func (c AppConfig) UnusedKeys() []string {
	var keys []string
	if len(c.SMTP) > 0 {
		keys = append(keys, "smtp")
	}
	return keys
}

// MailOn says whether the server sends email (config.json "gmail"), and so enrolls devices only by emailed links.
func (c AppConfig) MailOn() bool { return c.Gmail != nil && c.Gmail.ClientFile != "" }

// LoadConfig reads config.json (or another file) and fills in the defaults. Unknown keys are refused, so a typo
// (or a Journal config.json) doesn't pass silently; the keys the server stopped using are taken (UnusedKeys).
func LoadConfig(path string) (AppConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return AppConfig{}, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()
	var config AppConfig
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&config); err != nil {
		return AppConfig{}, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	return config.WithDefaults(), nil
}

// WithDefaults fills in the optional settings.
func (c AppConfig) WithDefaults() AppConfig {
	if c.Port == "" {
		c.Port = DefaultPort
	}
	if c.UsersFile == "" {
		c.UsersFile = DefaultUsersFile
	}
	if c.DevicesFile == "" {
		c.DevicesFile = DefaultDevicesFile
	}
	if c.PairsFile == "" {
		c.PairsFile = DefaultPairsFile
	}
	if c.LiveKit != nil {
		l := *c.LiveKit
		if l.ConfigFile == "" {
			l.ConfigFile = "livekit.yaml"
		}
		if l.KeysFile == "" {
			l.KeysFile = "livekit.keys"
		}
		if l.URL == "" {
			l.URL = "http://127.0.0.1:7880"
		}
		if l.TCPPort == 0 {
			l.TCPPort = 7881
		}
		if l.UDPPort == 0 {
			l.UDPPort = 7882
		}
		if l.MaxCallDevices == 0 {
			l.MaxCallDevices = DefaultMaxCallDevices
		}
		if l.KeepCallDays == 0 {
			l.KeepCallDays = DefaultKeepCallDays
		}
		c.LiveKit = &l
	}
	if c.BlobDir == "" {
		c.BlobDir = DefaultBlobDir
	}
	if c.BlobDays == 0 {
		c.BlobDays = DefaultBlobDays
	}
	if c.MaxBlobMB == 0 {
		c.MaxBlobMB = DefaultMaxBlobMB
	}
	if c.MediaDays == 0 {
		c.MediaDays = DefaultMediaDays
	}
	if c.MediaMaxDays == 0 {
		c.MediaMaxDays = DefaultMediaMaxDays
	}
	if c.MediaQuotaGB == 0 {
		c.MediaQuotaGB = DefaultMediaQuotaGB
	}
	if c.MinFreeGB == 0 {
		c.MinFreeGB = DefaultMinFreeGB
	}
	if c.GroupsFile == "" {
		c.GroupsFile = DefaultGroupsFile
	}
	if c.InvitesFile == "" {
		c.InvitesFile = DefaultInvitesFile
	}
	if c.DatabaseFile == "" {
		c.DatabaseFile = DefaultDatabaseFile
	}
	if c.QueueDays <= 0 {
		c.QueueDays = DefaultQueueDays
	}
	if c.AppReleases == "" {
		c.AppReleases = DefaultAppReleases
	}
	if c.AppReleaseFile == "" {
		c.AppReleaseFile = DefaultAppReleaseFile
	}
	if c.AdminAddr == "" {
		c.AdminAddr = DefaultAdminAddr
	}
	if c.AdminTokenFile == "" {
		c.AdminTokenFile = DefaultAdminTokenFile
	}
	return c
}
