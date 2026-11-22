package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/version"
)

const configPath = "config.json"

const usage = `usage:
  ptt-server                          run the server
  ptt-server version                  the version (version/VERSION) and build
  ptt-server user add <email> [name]  add a user (users.json), its email its identity; the name (its certificates'
                                      CN) is made from the email when omitted. Without gmail in config.json, a user
                                      may also be added by name alone: user add <name>
  ptt-server user email <user> <email>
                                      give a user added by name its email
  ptt-server user remove <name>       remove a user and revoke every certificate of its devices
  ptt-server users                    list the users and how many devices each has
  ptt-server enroll-code <user>       create a one-time enrollment code for a user (by name or email): with gmail in
                                      config.json the server mails the link to the user's email, else it is printed
                                      here with its QR code
  ptt-server mail-login [--no-browser]
                                      sign in to the Gmail account the links are sent from (config.json "gmail"),
                                      once, at this computer: the server keeps a send-only grant, not a password
  ptt-server devices [user]           list enrolled devices, with their device numbers
  ptt-server revoke <serial>          revoke an enrolled device
  ptt-server id                       this server's id, fingerprint and DHT key, as phones know it
  ptt-server discovery                check finding the server from this network: the routers that map ports, the
                                      addresses, publishing them in the BitTorrent DHT and finding them again
  ptt-server setup ...                make a server folder: config, certificates (docs/install.md;
                                      ptt-server setup --help)
  ptt-server service install|uninstall|start|stop|firewall
                                      the Windows service that starts the server at boot, with its firewall rules
                                      (as administrator); firewall makes only the rules
  ptt-server livekit update [version] put LiveKit's latest release (or that version) beside ptt-server, checked
                                      against its checksums, and have the running server restart LiveKit
  ptt-server app-update [--push]      read the app's latest GitHub release now and push app_update to the phones
                                      if it is new; --push pushes it even if it was announced before

The commands but setup, service, id, discovery and mail-login talk to the running server's admin API.
`

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("ptt-server", version.String())
		return
	}
	if len(os.Args) == 2 && (os.Args[1] == "help" || os.Args[1] == "--help" || os.Args[1] == "-h") {
		fmt.Print(usage)
		return
	}
	// These run before there is a config.json (setup makes it), or don't need it.
	if len(os.Args) >= 2 && (os.Args[1] == "setup" || os.Args[1] == "service") {
		run := runSetup
		if os.Args[1] == "service" {
			run = runServiceCommand
		}
		if err := run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if runAsService() {
		return
	}
	if _, err := auth.UseInstallFolder(configPath); err != nil {
		log.Fatal(err)
	}
	config, err := auth.LoadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}

	if len(os.Args) < 2 {
		serve(context.Background(), config, func() { os.Exit(0) })
		return
	}
	run := runAdminCommand
	switch os.Args[1] {
	case "livekit":
		run = liveKitCommand
	case "mail-login":
		run = func(config auth.AppConfig, _ string, args []string) error { return mailLoginCommand(config, args) }
	case "id", "discovery":
		run = func(config auth.AppConfig, command string, args []string) error {
			if len(args) > 0 {
				return fmt.Errorf("%s takes no arguments", command)
			}
			if command == "id" {
				return idCommand(config)
			}
			return discoveryCommand(config)
		}
	}
	if err := run(config, os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
