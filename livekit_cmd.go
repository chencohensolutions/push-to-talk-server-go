package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/chencohensolutions/push-to-talk-server-go/auth"
	"github.com/chencohensolutions/push-to-talk-server-go/livekit"
)

// liveKitProgram is where the livekit-server ptt-server runs is, or goes: config.json's livekit binary, or
// livekit-server(.exe) beside ptt-server.
func liveKitProgram(config auth.AppConfig) (string, error) {
	if !config.LiveKitOn() {
		return "", errors.New(`config.json has no "livekit" (docs/install.md, "LiveKit")`)
	}
	if config.LiveKit.Binary == "none" {
		return "", errors.New(`config.json's livekit binary is "none": LiveKit is started some other way, so update it there`)
	}
	if config.LiveKit.Binary != "" {
		return config.LiveKit.Binary, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	name := "livekit-server"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(exe), name), nil
}

// liveKitCommand is `ptt-server livekit update [version]`: it puts LiveKit's latest release (or version) where
// ptt-server runs it, then has the running server restart LiveKit.
func liveKitCommand(config auth.AppConfig, command string, args []string) error {
	if len(args) < 1 || args[0] != "update" || len(args) > 2 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("usage: ptt-server livekit update [version]")
	}
	tag := ""
	if len(args) == 2 {
		tag = args[1]
	}
	program, err := liveKitProgram(config)
	if err != nil {
		return err
	}
	u := &livekit.Updater{}
	done, err := u.Update(context.Background(), program, tag)
	if err != nil {
		return err
	}
	switch {
	case done.Same:
		fmt.Printf("LiveKit %s is already at %s\n", done.New, program)
		return nil
	case done.Old == "":
		fmt.Printf("LiveKit %s installed at %s\n", done.New, program)
	default:
		fmt.Printf("LiveKit %s -> %s at %s (the old program is kept as %s.old)\n", done.Old, done.New, program, filepath.Base(program))
	}
	var data struct {
		RestartLiveKit bool `json:"restartLiveKit"`
	}
	if err := adminQuery(config, `mutation { restartLiveKit }`, nil, &data); err != nil {
		fmt.Printf("The server isn't reachable (%v); it runs the new LiveKit when it starts.\n", err)
		return nil
	}
	if data.RestartLiveKit {
		fmt.Println("The server is restarting LiveKit with it (live talk and calls drop for a few seconds).")
	} else {
		fmt.Println("The running server doesn't run LiveKit; restart ptt-server to start the new one.")
	}
	return nil
}
