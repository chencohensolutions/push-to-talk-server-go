package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/discovery"
	"github.com/skip2/go-qrcode"
)

// runAdminCommand implements user add / user remove / users / enroll-code / devices / revoke as GraphQL calls to
// the running server's admin API.
func runAdminCommand(config auth.AppConfig, command string, args []string) error {
	switch {
	case command == "user" && len(args) == 2 && args[0] == "add":
		return userAddCommand(config, args[1])
	case command == "user" && len(args) == 2 && args[0] == "remove":
		return userRemoveCommand(config, args[1])
	case command == "users" && len(args) == 0:
		return usersCommand(config)
	case command == "enroll-code" && len(args) == 1:
		return enrollCodeCommand(config, args[0])
	case command == "devices" && len(args) <= 1:
		return devicesCommand(config, args)
	case command == "revoke" && len(args) == 1:
		return revokeCommand(config, args[0])
	case command == "app-update" && (len(args) == 0 || len(args) == 1 && args[0] == "--push"):
		return appUpdateCommand(config, len(args) == 1)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command or wrong arguments: %s", strings.Join(append([]string{command}, args...), " "))
	}
}

type adminDevice struct {
	Serial        string     `json:"serial"`
	User          string     `json:"user"`
	Name          string     `json:"name"`
	DeviceNumber  int        `json:"deviceNumber"`
	KeyProtection string     `json:"keyProtection"`
	RegisteredAt  time.Time  `json:"registeredAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	RevokedAt     *time.Time `json:"revokedAt"`
	RenewedFrom   *string    `json:"renewedFrom"`
}

const deviceFields = "serial user name deviceNumber keyProtection registeredAt expiresAt revokedAt renewedFrom"

func userAddCommand(config auth.AppConfig, name string) error {
	var data struct {
		AddUser struct{ Name string } `json:"addUser"`
	}
	if err := adminQuery(config, `mutation($name: String!) { addUser(name: $name) { name } }`,
		map[string]any{"name": name}, &data); err != nil {
		return err
	}
	fmt.Printf("Added user %s. Enroll a phone with: ptt-server enroll-code %s\n", data.AddUser.Name, data.AddUser.Name)
	return nil
}

func userRemoveCommand(config auth.AppConfig, name string) error {
	var data struct {
		RemoveUser struct {
			Name           string
			RevokedDevices int
		} `json:"removeUser"`
	}
	if err := adminQuery(config, `mutation($name: String!) { removeUser(name: $name) { name revokedDevices } }`,
		map[string]any{"name": name}, &data); err != nil {
		return err
	}
	fmt.Printf("Removed user %s and revoked %d of its devices\n", data.RemoveUser.Name, data.RemoveUser.RevokedDevices)
	return nil
}

func usersCommand(config auth.AppConfig) error {
	var data struct {
		Users []struct {
			Name    string
			AddedAt time.Time
			Devices int
		} `json:"users"`
	}
	if err := adminQuery(config, `{ users { name addedAt devices } }`, nil, &data); err != nil {
		return err
	}
	if len(data.Users) == 0 {
		fmt.Println("No users. Add one with: ptt-server user add <name>")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "USER\tADDED\tDEVICES")
	for _, u := range data.Users {
		fmt.Fprintf(w, "%s\t%s\t%d\n", u.Name, u.AddedAt.Local().Format(time.DateOnly), u.Devices)
	}
	return w.Flush()
}

func enrollCodeCommand(config auth.AppConfig, user string) error {
	var data struct {
		CreateEnrollmentCode struct {
			Code      string    `json:"code"`
			User      string    `json:"user"`
			ExpiresAt time.Time `json:"expiresAt"`
			ServerURL *string   `json:"serverUrl"`
		} `json:"createEnrollmentCode"`
	}
	err := adminQuery(config, `mutation($user: String!) {
		createEnrollmentCode(user: $user) { code user expiresAt serverUrl }
	}`, map[string]any{"user": user}, &data)
	if err != nil {
		return err
	}
	code := data.CreateEnrollmentCode
	// Who this server is and where, so the phone can pin its key from the first connection and find it without a
	// host name the certificate lists (docs/authentication.md, "Enrolling by QR code").
	var found *enrollDiscovery
	if d, err := openDiscovery(config); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		found = &enrollDiscovery{Fingerprint: d.fingerprint, Addresses: d.publisher.Addresses(ctx)}
		cancel()
		if d.key != nil {
			found.Key = hex.EncodeToString(d.key.Public().(ed25519.PublicKey))
		}
		if code.ServerURL == nil && len(found.Addresses) > 0 {
			code.ServerURL = &found.Addresses[0]
		}
	}
	fmt.Printf("Enrollment code for user %q\n\n", code.User)
	if code.ServerURL != nil {
		fmt.Printf("  Server   %s\n", *code.ServerURL)
	} else {
		fmt.Printf("  Server   (set public_url in config.json to show the address here)\n")
	}
	if found != nil {
		fmt.Printf("  Id       %s\n", discovery.FormatID(found.Fingerprint))
	}
	fmt.Printf("  Code     %s\n", code.Code)
	fmt.Printf("  Expires  %s (in %d min), single use\n", code.ExpiresAt.Local().Format("15:04"), int(time.Until(code.ExpiresAt).Round(time.Minute).Minutes()))
	link := enrollmentLink(code.Code, code.ServerURL, found)
	qr, err := qrcode.New(link, qrcode.Medium)
	if err != nil {
		return err
	}
	fmt.Printf("\nScan with the phone's camera to open the app with this code:\n\n%s\n  %s\n", terminalQR(qr), link)
	return nil
}

// terminalQR draws qr two rows to a line, white on black whatever the terminal's colors, so it is never inverted
// (some cameras don't read an inverted code).
func terminalQR(qr *qrcode.QRCode) string {
	var b strings.Builder
	for line := range strings.SplitSeq(strings.TrimRight(qr.ToSmallString(false), "\n"), "\n") {
		b.WriteString("\x1b[97;40m")
		b.WriteString(line)
		b.WriteString("\x1b[0m\n")
	}
	return b.String()
}

// enrollDiscovery is who the server is and where, for the enrollment link.
type enrollDiscovery struct {
	Fingerprint string   // discovery.Fingerprint of the server certificate
	Key         string   // the DHT key, hex; "" with discovery off
	Addresses   []string // https://host:port, the most likely first
}

// enrollmentLink is what the enrollment QR code holds: ptt://enroll?code=…&server=…, which opens the app's
// enrollment on that code. Without a server the app keeps the address it has. With found it also carries
// fingerprint=… (the app checks the server's key against it instead of the host name, from the first connection),
// key=… (to look the server up in the DHT when no address answers) and address=… for each of the server's
// addresses (at most 6).
func enrollmentLink(code string, serverURL *string, found *enrollDiscovery) string {
	query := url.Values{"code": {code}}
	if serverURL != nil {
		query.Set("server", *serverURL)
	}
	if found != nil {
		query.Set("fingerprint", found.Fingerprint)
		if found.Key != "" {
			query.Set("key", found.Key)
		}
		for _, a := range found.Addresses[:min(len(found.Addresses), 6)] {
			query.Add("address", a)
		}
	}
	return "ptt://enroll?" + query.Encode()
}

func devicesCommand(config auth.AppConfig, args []string) error {
	variables := map[string]any{}
	if len(args) == 1 {
		variables["user"] = args[0]
	}
	var data struct {
		Devices []adminDevice `json:"devices"`
	}
	if err := adminQuery(config, `query($user: String) { devices(user: $user) { `+deviceFields+` } }`, variables, &data); err != nil {
		return err
	}
	if len(data.Devices) == 0 {
		fmt.Println("No enrolled devices.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "USER\tNO.\tDEVICE\tKEY\tREGISTERED\tEXPIRES\tSTATUS\tSERIAL")
	for _, d := range data.Devices {
		name := d.Name
		if d.RenewedFrom != nil {
			name += " (renewed)"
		}
		status := "active"
		if d.RevokedAt != nil {
			status = "revoked " + d.RevokedAt.Local().Format(time.DateOnly)
		} else if time.Now().After(d.ExpiresAt) {
			status = "expired"
		}
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", d.User, d.DeviceNumber, name, d.KeyProtection,
			d.RegisteredAt.Local().Format(time.DateOnly), d.ExpiresAt.Local().Format(time.DateOnly), status, d.Serial)
	}
	return w.Flush()
}

func revokeCommand(config auth.AppConfig, serial string) error {
	var data struct {
		RevokeDevice adminDevice `json:"revokeDevice"`
	}
	err := adminQuery(config, `mutation($serial: String!) { revokeDevice(serial: $serial) { `+deviceFields+` } }`,
		map[string]any{"serial": serial}, &data)
	if err != nil {
		return err
	}
	d := data.RevokeDevice
	fmt.Printf("Revoked %q, device %d of user %s (serial %s)\n", d.Name, d.DeviceNumber, d.User, d.Serial)
	return nil
}

func adminQuery(config auth.AppConfig, query string, variables map[string]any, out any) error {
	token, err := readAdminToken(config.AdminTokenFile)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+config.AdminAddr+"/admin/query", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the admin API at %s (is the server running?): %w", config.AdminAddr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin API returned %s", resp.Status)
	}

	var result struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	if len(result.Errors) > 0 {
		return fmt.Errorf("%s", result.Errors[0].Message)
	}
	return json.Unmarshal(result.Data, out)
}

// appUpdateCommand is `ptt-server app-update [--push]`: the server reads the app's latest release now, and pushes
// app_update to the phones when it is new, or with --push either way (docs/install.md, "App updates").
func appUpdateCommand(config auth.AppConfig, push bool) error {
	var data struct {
		CheckAppRelease struct {
			Tag     string `json:"tag"`
			Version string `json:"version"`
			New     bool   `json:"new"`
			Pushed  int    `json:"pushed"`
		} `json:"checkAppRelease"`
	}
	if err := adminQuery(config, `mutation($push: Boolean!) { checkAppRelease(push: $push) { tag version new pushed } }`,
		map[string]any{"push": push}, &data); err != nil {
		return err
	}
	c := data.CheckAppRelease
	switch {
	case c.Pushed > 0:
		fmt.Printf("The latest release is %s (Talk %s). Pushed app_update to %d devices.\n", c.Tag, c.Version, c.Pushed)
	case push || c.New:
		fmt.Printf("The latest release is %s (Talk %s). No device has a push token (or push is off), so none was told.\n", c.Tag, c.Version)
	default:
		fmt.Printf("The latest release is %s (Talk %s), already announced. Nothing pushed; --push sends it again.\n", c.Tag, c.Version)
	}
	return nil
}
