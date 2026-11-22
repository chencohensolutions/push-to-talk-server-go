package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/mail"
)

// mailLoginCommand signs in to the Gmail account the enrollment links are sent from (config.json "gmail") and keeps its
// send-only grant in the token file. It needs a browser on this computer, or the printed address opened on another
// one that can reach back to this computer's loopback (in practice: run it where the server runs, at its desktop).
func mailLoginCommand(config auth.AppConfig, args []string) error {
	noBrowser := false
	for _, a := range args {
		switch a {
		case "--no-browser":
			noBrowser = true
		default:
			return fmt.Errorf("mail-login takes only --no-browser, not %q", a)
		}
	}
	if config.Gmail == nil {
		return errors.New(`config.json has no "gmail": add {"gmail": {"client_file": "gmail-client.json"}} (docs/install.md, "Email")`)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	email, err := mail.Login(ctx, *config.Gmail, func(url string) {
		fmt.Println("Sign in to the Google account to send from, and allow \"Send email on your behalf\":")
		fmt.Println()
		fmt.Println("  " + url)
		fmt.Println()
		if !noBrowser {
			openBrowser(url)
		}
		fmt.Println("Waiting for the sign-in (10 minutes)...")
	})
	if err != nil {
		return err
	}
	fmt.Printf("Signed in: enrollment links will be sent from %s. Restart the server to use it.\n", email)
	fmt.Println("To stop it, remove ptt-server's access in your Google account (Security, Third-party access).")
	return nil
}

// openBrowser opens url in the default browser; when it can't, the printed address is there to copy.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
