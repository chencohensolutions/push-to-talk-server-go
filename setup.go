package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/certs"
	"github.com/chencohensolutions/push-to-talk-server-go/enroll"
	"github.com/chencohensolutions/push-to-talk-server-go/livekit"
)

const setupUsage = `usage:
  ptt-server setup --dir <folder> [--user <name>] [--import-ca <folder>] [options]
      a new server with its own new CA (--import-ca uses ca.pem and ca-key.pem from another server instead), and
      its first user when --user is given (more with ptt-server user add)
  ptt-server setup --dir <folder> --move-from <old server folder> [options]
      a server moved from another PC: copies its config.json, certificates, users.json, devices.json, pairs.json
      and ptt.db (only reads them; stop the old server first)

Run it again at any time: what is there is kept, and only what is missing is made.

options:
`

// setupOptions is what ptt-server setup was asked to do (docs/install.md).
type setupOptions struct {
	dir               string
	moveFrom          string
	user              string
	importCA          string
	newCA             bool
	addresses         []string
	port              string
	reissueServerCert bool
}

// runSetup makes or completes a server folder: config.json, users.json and the certificates. It writes only inside
// --dir: the folder moved from, and files already in --dir, are never changed.
func runSetup(args []string) error {
	o, err := parseSetupArgs(args)
	if err != nil {
		return err
	}
	return setup(context.Background(), o)
}

func parseSetupArgs(args []string) (setupOptions, error) {
	o := setupOptions{}
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), setupUsage)
		fs.PrintDefaults()
	}
	fs.StringVar(&o.dir, "dir", ".", "the server's folder (made if missing)")
	fs.StringVar(&o.moveFrom, "move-from", "", "the folder of the server this one replaces")
	fs.StringVar(&o.user, "user", "", "a first user to add to users.json")
	fs.StringVar(&o.importCA, "import-ca", "", "folder with ca.pem and ca-key.pem: another server's CA, to keep its devices (default: a new CA)")
	fs.BoolVar(&o.newCA, "new-ca", false, "make a new CA where config.json names one that is missing (every device must enroll again)")
	fs.Func("address", "a name or IP address devices reach the server by, beside this PC's own (repeatable; the first is public_url)", func(s string) error {
		o.addresses = append(o.addresses, s)
		return nil
	})
	fs.StringVar(&o.port, "port", "", "port devices connect to (default "+auth.DefaultPort+")")
	fs.BoolVar(&o.reissueServerCert, "reissue-server-cert", false, "make the server certificate again for this PC's addresses (the old one is kept as .bak)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.NArg() != 0 {
		return o, fmt.Errorf("unexpected %q (ptt-server setup --help)", fs.Arg(0))
	}
	switch {
	case o.moveFrom != "" && (o.newCA || o.importCA != ""):
		return o, errors.New("--move-from takes the CA from the old server; leave out --import-ca and --new-ca")
	case o.importCA != "" && o.newCA:
		return o, errors.New("--import-ca or --new-ca, not both")
	}
	if o.user != "" {
		if err := auth.CheckUserName(o.user); err != nil {
			return o, err
		}
	}
	// Folders given relative to where setup was started, before it changes to --dir.
	for _, p := range []*string{&o.dir, &o.moveFrom, &o.importCA} {
		if *p != "" {
			abs, err := filepath.Abs(*p)
			if err != nil {
				return o, err
			}
			*p = abs
		}
	}
	return o, nil
}

func setup(_ context.Context, o setupOptions) error {
	if o.moveFrom != "" && samePath(o.moveFrom, o.dir) {
		return errors.New("--move-from is the folder being set up; give the new server its own --dir")
	}
	if err := os.MkdirAll(o.dir, 0o755); err != nil {
		return err
	}
	if err := os.Chdir(o.dir); err != nil {
		return err
	}
	fmt.Printf("Setting up the server in %s\n", o.dir)

	// 1. config.json
	newServer := false
	switch _, err := os.Stat(configPath); {
	case err == nil:
		fmt.Printf("config.json: kept\n")
	case o.moveFrom != "":
		if err := moveServer(o.moveFrom); err != nil {
			return err
		}
	default:
		if err := writeNewConfig(o); err != nil {
			return err
		}
		newServer = true
	}
	config, err := auth.LoadConfig(configPath)
	if err != nil {
		return err
	}

	// 2. users.json
	users, err := auth.OpenUsers(config.UsersFile)
	if err != nil {
		return err
	}
	if o.user != "" {
		if users.Find(o.user) != nil {
			fmt.Printf("User %s: kept\n", o.user)
		} else if _, err := users.Add(o.user, time.Now()); err != nil {
			return err
		} else {
			fmt.Printf("User %s: added to %s\n", o.user, config.UsersFile)
		}
	}

	// 3. Certificates
	if err := setupCertificates(o, config, newServer); err != nil {
		return err
	}

	// 4. LiveKit's config and keys (the live talk path), when config.json has "livekit"
	if err := setupLiveKit(config); err != nil {
		return err
	}

	// 5. What's next
	fmt.Printf("\nReady. Devices connect to %s (port %s).\n", orNone(config.PublicURL), config.Port)
	fmt.Printf("Start the server with ptt-server (in %s), then:\n", o.dir)
	list := users.List()
	if len(list) == 0 {
		fmt.Printf("  ptt-server user add <name>\n  ptt-server enroll-code <name>\n")
	} else {
		fmt.Printf("  ptt-server enroll-code %s\n", list[0].Name)
	}
	return nil
}

// moveServer copies the old server's config.json, the certificates it names, its users, its device registry, its
// pairs and its database (with SQLite's write-ahead log, when the old server didn't stop cleanly) into the current
// folder. The old folder is only read; admin.token isn't copied (the server writes a new one at
// start).
func moveServer(from string) error {
	old, err := auth.LoadConfig(filepath.Join(from, configPath))
	if err != nil {
		return err
	}
	if err := copyNew(filepath.Join(from, configPath), configPath); err != nil {
		return err
	}
	fmt.Printf("config.json: copied from %s\n", from)
	optional := []string{old.UsersFile, old.DevicesFile, enroll.RevokedPath(old.DevicesFile), old.PairsFile,
		old.DatabaseFile, old.DatabaseFile + "-wal"}
	files := append([]string{old.TLSCert, old.TLSKey, old.ClientCA, old.ClientCAKey}, optional...)
	for _, name := range files {
		if name == "" {
			continue
		}
		if filepath.IsAbs(name) {
			fmt.Printf("  ! %s is a full path in config.json: copy it to this PC yourself if it isn't here\n", name)
			continue
		}
		switch err := copyNew(filepath.Join(from, name), name); {
		case err == nil:
			fmt.Printf("%s: copied\n", filepath.ToSlash(name))
		case errors.Is(err, os.ErrExist):
			fmt.Printf("%s: kept\n", filepath.ToSlash(name))
		case errors.Is(err, os.ErrNotExist) && slices.Contains(optional, name):
			// A server nobody has enrolled with yet has no registry, and one with no users no users.json.
		default:
			return err
		}
	}
	return nil
}

// newConfig is the config.json setup writes: only what it sets, so the server's defaults apply to the rest.
type newConfig struct {
	TLSCert     string `json:"tls_cert"`
	TLSKey      string `json:"tls_key"`
	ClientCA    string `json:"client_ca"`
	ClientCAKey string `json:"client_ca_key"`
	// A new server has only the devices it enrolls: any other certificate is refused (docs/authentication.md).
	EnrolledOnly bool   `json:"enrolled_only"`
	PublicURL    string `json:"public_url,omitempty"`
	Port         string `json:"port,omitempty"`
	// The live talk path: on for a new server, with every LiveKit setting at its default.
	LiveKit *auth.LiveKitConfig `json:"livekit"`
}

func writeNewConfig(o setupOptions) error {
	port := o.port
	if port == "" {
		port = auth.DefaultPort
	}
	config := newConfig{
		TLSCert: "certs/server.pem", TLSKey: "certs/server-key.pem",
		ClientCA: "certs/ca.pem", ClientCAKey: "certs/ca-key.pem", EnrolledOnly: true, LiveKit: &auth.LiveKitConfig{},
	}
	if o.port != "" && o.port != auth.DefaultPort {
		config.Port = o.port
	}
	if address := firstAddress(o.addresses); address != "" {
		config.PublicURL = "https://" + address + ":" + port
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := writeNew(configPath, append(data, '\n')); err != nil {
		return err
	}
	fmt.Printf("config.json: written\n")
	return nil
}

func setupCertificates(o setupOptions, config auth.AppConfig, newServer bool) error {
	var ca certs.CA
	var err error
	switch {
	case exists(config.ClientCA) && exists(config.ClientCAKey):
		if ca, err = certs.LoadCA(config.ClientCA, config.ClientCAKey); err != nil {
			return err
		}
		fmt.Printf("CA: kept\n")
	case o.importCA != "":
		if ca, err = certs.LoadCA(filepath.Join(o.importCA, "ca.pem"), filepath.Join(o.importCA, "ca-key.pem")); err != nil {
			return err
		}
		for from, to := range map[string]string{"ca.pem": config.ClientCA, "ca-key.pem": config.ClientCAKey} {
			if err := copyNew(filepath.Join(o.importCA, from), to); err != nil {
				return err
			}
		}
		fmt.Printf("CA: copied from %s\n", o.importCA)
	case !newServer && !o.newCA:
		// A server that has devices keeps the CA they trust: a new one would lock them all out.
		return fmt.Errorf("no CA at %s: put back ca.pem and ca-key.pem, or give --import-ca <folder> (--new-ca makes "+
			"a new one, and every device must enroll again)", config.ClientCA)
	default:
		// Each server has its own CA: the apps learn it when they enroll by the QR code (docs/install.md).
		if ca, err = certs.NewCA(config.ClientCA, config.ClientCAKey); err != nil {
			return err
		}
		fmt.Printf("CA: made this server's own.\n" +
			"  Phones enroll by scanning the QR code ptt-server enroll-code prints, which tells them this\n" +
			"  server's key; they keep its CA from then on. Keep certs/ca-key.pem private and backed up.\n")
	}

	// The names devices may use: this PC's own, and the ones asked for.
	names := certs.LocalNames()
	for _, a := range o.addresses {
		if !slices.Contains(names, a) {
			names = append(names, a)
		}
	}
	if exists(config.TLSCert) && exists(config.TLSKey) {
		missing, err := certs.Missing(config.TLSCert, append(certs.PrivateAddresses(), o.addresses...))
		if err != nil {
			return err
		}
		if len(missing) == 0 {
			fmt.Printf("Server certificate: kept\n")
			return nil
		}
		if !o.reissueServerCert {
			fmt.Printf("Server certificate: kept, but it isn't valid for %s.\n"+
				"  Phones that enrolled by the QR code check the server's key, not its names, so they still connect.\n"+
				"  Run setup again with --reissue-server-cert to add them.\n", strings.Join(missing, ", "))
			return nil
		}
		for _, p := range []string{config.TLSCert, config.TLSKey} {
			if err := keepAsBackup(p); err != nil {
				return err
			}
		}
		fmt.Printf("  ! A new server key changes the server's id: phones enrolled by the QR code must enroll again.\n")
	}
	if err := certs.NewServerCert(ca, config.TLSCert, config.TLSKey, names); err != nil {
		return err
	}
	fmt.Printf("Server certificate: made for %s\n", strings.Join(names, ", "))
	return nil
}

// firstAddress is the address public_url names: the first one asked for, else this PC's first private address.
func firstAddress(asked []string) string {
	if len(asked) > 0 {
		return asked[0]
	}
	if addrs := certs.PrivateAddresses(); len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

// copyNew copies a file to a path that must not exist yet (os.ErrExist if it does); from is only read.
func copyNew(from, to string) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close()
	info, err := src.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return err
	}
	dst, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(to)
		return err
	}
	return dst.Close()
}

// writeNew writes a file that must not exist yet.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}

// keepAsBackup renames path to path.bak (or path.<time>.bak when that is taken), so nothing is lost.
func keepAsBackup(path string) error {
	backup := path + ".bak"
	if exists(backup) {
		backup = path + "." + time.Now().Format("20060102-150405") + ".bak"
	}
	if err := os.Rename(path, backup); err != nil {
		return err
	}
	fmt.Printf("%s: kept as %s\n", filepath.ToSlash(path), filepath.ToSlash(backup))
	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// samePath reports whether two absolute paths name the same folder (ignoring case on Windows and macOS, whose
// file systems usually do).
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "linux" {
		return a == b
	}
	return strings.EqualFold(a, b)
}

func orNone(s string) string {
	if s == "" {
		return "(no public_url in config.json)"
	}
	return s
}

// setupLiveKit writes LiveKit's key file and config when config.json has "livekit" and they are missing; ones there
// are kept. The key file is a secret: LiveKit and ptt-server read it, nothing else.
func setupLiveKit(config auth.AppConfig) error {
	if !config.LiveKitOn() {
		fmt.Printf("LiveKit: off (add \"livekit\": {} to config.json and run setup again for the live talk path)\n")
		return nil
	}
	l := config.LiveKit
	if exists(l.KeysFile) {
		if _, err := livekit.LoadKeys(l.KeysFile); err != nil {
			return err
		}
		fmt.Printf("%s: kept\n", l.KeysFile)
	} else {
		keys := livekit.NewKeys()
		if err := writeSecret(l.KeysFile, []byte(keys.Key+": "+keys.Secret+"\n")); err != nil {
			return err
		}
		fmt.Printf("%s: made (LiveKit's API key and secret)\n", l.KeysFile)
	}
	if exists(l.ConfigFile) {
		fmt.Printf("%s: kept\n", l.ConfigFile)
	} else {
		u, err := url.Parse(l.URL)
		if err != nil {
			return fmt.Errorf("livekit url: %w", err)
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return fmt.Errorf("livekit url %s names no port", l.URL)
		}
		if err := writeNew(l.ConfigFile, []byte(livekit.ConfigYAML(port, l.TCPPort, l.UDPPort, l.KeysFile))); err != nil {
			return err
		}
		fmt.Printf("%s: written (signalling on %s, media on UDP %d and TCP %d)\n", l.ConfigFile, l.URL, l.UDPPort, l.TCPPort)
	}
	if liveKitBinary(config) == "" && l.Binary != "none" {
		fmt.Printf("LiveKit: put livekit-server beside ptt-server (docs/install.md, \"LiveKit\"); ptt-server runs it\n")
	}
	return nil
}

// writeSecret writes a new file only its owner reads.
func writeSecret(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	return f.Close()
}
