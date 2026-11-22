// Package auth holds the server's configuration, its users (users.json) and the identity of a request: the user
// and device that the client certificate named. See docs/authentication.md.
package auth

import (
	"encoding/json"
	"fmt"
	"os"
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
	// The SQLite database (default ptt.db): the devices' public prekeys and the message queue.
	DatabaseFile string `json:"database_file"`
	// Days an envelope waits in the queue for a device that doesn't take it (default 30).
	QueueDays int `json:"queue_days"`
	// Let enrolled users invite friends (createInvite): one link and its passcode, sent from the inviter's phone,
	// that enroll the friend and pair them with whoever invited them (docs/authentication.md, "Invites"). On unless
	// set to false.
	Invites *bool `json:"invites"`
	// The invites waiting to be used (default invites.json).
	InvitesFile string `json:"invites_file"`
	// No longer used: until 2026-11-22 the server emailed invite codes, over SMTP or the Gmail API. Since then the
	// inviter's phone sends every invite, and the server sends no mail. Taken and ignored, so a config.json from then
	// still starts the server (UnusedKeys says so in the log).
	SMTP  json.RawMessage `json:"smtp,omitempty"`
	Gmail json.RawMessage `json:"gmail,omitempty"`
	// Loopback-only listener for the admin GraphQL API (default 127.0.0.1:8082).
	AdminAddr string `json:"admin_addr"`
	// Token for the admin API, rewritten on every server start (default admin.token).
	AdminTokenFile string `json:"admin_token_file"`
}

const (
	DefaultPort           = "56400"
	DefaultUsersFile      = "users.json"
	DefaultDevicesFile    = "devices.json"
	DefaultPairsFile      = "pairs.json"
	DefaultInvitesFile    = "invites.json"
	DefaultDatabaseFile   = "ptt.db"
	DefaultQueueDays      = 30
	DefaultAdminAddr      = "127.0.0.1:8082"
	DefaultAdminTokenFile = "admin.token"
)

// DiscoveryOn says whether the server uses the DHT: on unless config.json sets "discovery": false.
func (c AppConfig) DiscoveryOn() bool { return c.Discovery == nil || *c.Discovery }

// InvitesOn says whether users may invite friends: on unless "invites": false.
func (c AppConfig) InvitesOn() bool { return c.Invites == nil || *c.Invites }

// PortMappingOn says whether the server asks the router to forward its port: on unless "port_mapping": false.
func (c AppConfig) PortMappingOn() bool { return c.PortMapping == nil || *c.PortMapping }

// UnusedKeys are the keys config.json has that the server no longer uses ("smtp", "gmail"), to say so in the log.
func (c AppConfig) UnusedKeys() []string {
	var keys []string
	if len(c.SMTP) > 0 {
		keys = append(keys, "smtp")
	}
	if len(c.Gmail) > 0 {
		keys = append(keys, "gmail")
	}
	return keys
}

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
	if c.InvitesFile == "" {
		c.InvitesFile = DefaultInvitesFile
	}
	if c.DatabaseFile == "" {
		c.DatabaseFile = DefaultDatabaseFile
	}
	if c.QueueDays <= 0 {
		c.QueueDays = DefaultQueueDays
	}
	if c.AdminAddr == "" {
		c.AdminAddr = DefaultAdminAddr
	}
	if c.AdminTokenFile == "" {
		c.AdminTokenFile = DefaultAdminTokenFile
	}
	return c
}
