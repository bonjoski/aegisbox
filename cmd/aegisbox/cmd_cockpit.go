package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

func runCockpit(ctx context.Context, args []string) error {
	cockpitFlags := flag.NewFlagSet("cockpit", flag.ExitOnError)
	detach := cockpitFlags.Bool("detach", false, "Run Aegisbox Cockpit detached in the background")
	cockpitFlags.BoolVar(detach, "d", false, "Run Aegisbox Cockpit detached in the background (shorthand)")

	cockpitFlags.Usage = func() {
		fmt.Println("Usage: aegisbox cockpit [flags]")
		cockpitFlags.PrintDefaults()
	}

	if err := cockpitFlags.Parse(args); err != nil {
		return err
	}

	cockpitPath, isAppBundle, err := findAegisboxCockpit()
	if err != nil {
		return err
	}

	var cmd *exec.Cmd
	if isAppBundle && runtime.GOOS == "darwin" {
		cmdArgs := []string{"-a", cockpitPath}
		if !*detach {
			cmdArgs = append(cmdArgs, "-W") // wait for app to terminate
		}
		cmd = exec.CommandContext(ctx, "open", cmdArgs...)
	} else {
		cmd = exec.CommandContext(ctx, cockpitPath, cockpitFlags.Args()...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
	}

	if *detach {
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start Aegisbox Cockpit: %w", err)
		}
		fmt.Printf("🚀 Started Aegisbox Cockpit (PID %d)\n", cmd.Process.Pid)
		return nil
	}

	return cmd.Run()
}

func findAegisboxCockpit() (path string, isAppBundle bool, err error) {
	// 1. Check PATH for aegisbox-cockpit or aegisbox-desktop
	for _, name := range []string{"aegisbox-cockpit", "aegisbox-desktop"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, false, nil
		}
	}

	// 2. Check adjacent to current executable
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, name := range []string{"aegisbox-cockpit", "aegisbox-desktop"} {
			candidate := filepath.Join(dir, name)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, false, nil
			}
		}
		for _, appName := range []string{
			filepath.Join(dir, "Aegisbox Cockpit.app"),
			filepath.Join(dir, "..", "Aegisbox Cockpit.app"),
		} {
			if info, err := os.Stat(appName); err == nil && info.IsDir() {
				return appName, true, nil
			}
		}
	}

	// 3. macOS standard application folders
	if runtime.GOOS == "darwin" {
		home := os.Getenv("HOME")
		appPaths := []string{
			"/Applications/Aegisbox Cockpit.app",
			filepath.Join(home, "Applications/Aegisbox Cockpit.app"),
		}
		for _, app := range appPaths {
			if info, err := os.Stat(app); err == nil && info.IsDir() {
				return app, true, nil
			}
		}
	}

	// 4. Local workspace development paths
	devPaths := []string{
		"bin/Aegisbox Cockpit.app",
		"desktop/src-tauri/target/release/aegisbox-desktop",
		"desktop/src-tauri/target/debug/aegisbox-desktop",
	}
	for _, dev := range devPaths {
		if info, err := os.Stat(dev); err == nil {
			if filepath.Ext(dev) == ".app" && info.IsDir() {
				return dev, true, nil
			}
			if !info.IsDir() {
				return dev, false, nil
			}
		}
	}

	return "", false, fmt.Errorf("aegisbox-cockpit not found on PATH or in /Applications.\nBuild with 'cd desktop && npm run build && cd src-tauri && cargo build --release' or install via Homebrew")
}
