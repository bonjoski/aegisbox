package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"text/tabwriter"
	"time"

	"github.com/bonjoski/aegisbox/pkg/ipc"
	"github.com/bonjoski/aegisbox/pkg/version"
)

func runDaemon(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return printDaemonUsage()
	}

	sub := args[0]
	switch sub {
	case "status":
		return daemonStatus(ctx)
	case "start":
		return daemonStart(ctx)
	case "stop":
		return daemonStop(ctx)
	default:
		return fmt.Errorf("unknown daemon subcommand %q", sub)
	}
}

func printDaemonUsage() error {
	fmt.Println(`Manage the headless Aegisbox orchestration daemon (aegisboxd).

Usage:
  aegisbox daemon <command>

Commands:
  status   Check if aegisboxd is running and display session/feature status
  start    Launch aegisboxd in the background
  stop     Gracefully terminate the running aegisboxd service`)
	return nil
}

func daemonStatus(ctx context.Context) error {
	socketPath, err := ipc.DefaultSocketPath()
	if err != nil {
		return err
	}

	dialCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()

	client, err := ipc.NewClient(dialCtx, socketPath)
	if err != nil {
		fmt.Printf("● aegisboxd is NOT running (could not connect to %s)\n", socketPath)
		return nil
	}
	defer client.Close()

	resp, err := client.Authenticate(dialCtx, version.Version)
	if err != nil {
		return fmt.Errorf("failed to authenticate with daemon: %w", err)
	}

	hb, err := client.Heartbeat(dialCtx)
	if err != nil {
		return fmt.Errorf("failed to query daemon heartbeat: %w", err)
	}

	fmt.Printf("● aegisboxd is RUNNING\n\n")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  Daemon Version:\t%s\n", resp.DaemonVersion)
	fmt.Fprintf(w, "  Socket Path:\t%s\n", socketPath)
	fmt.Fprintf(w, "  Health Status:\t%v\n", hb.IsHealthy)
	fmt.Fprintf(w, "  Supported Features:\t%v\n", resp.SupportedFeatures)
	_ = w.Flush()
	return nil
}

func daemonStart(ctx context.Context) error {
	socketPath, err := ipc.DefaultSocketPath()
	if err != nil {
		return err
	}

	// Check if already running
	dialCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	client, err := ipc.NewClient(dialCtx, socketPath)
	cancel()
	if err == nil {
		_ = client.Close()
		fmt.Println("aegisboxd is already running.")
		return nil
	}

	// Find aegisboxd executable
	daemonBin, err := exec.LookPath("aegisboxd")
	if err != nil {
		// Fallback to executable directory
		self, _ := os.Executable()
		candidate := fmt.Sprintf("%s/aegisboxd", os.Getenv("GOPATH")+"/bin")
		if _, err := os.Stat(candidate); err == nil {
			daemonBin = candidate
		} else {
			daemonBin = self + "d" // e.g. /usr/local/bin/aegisboxd
		}
	}

	cmd := exec.Command(daemonBin)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to spawn aegisboxd: %w", err)
	}

	fmt.Printf("Started aegisboxd (PID %d)\n", cmd.Process.Pid)
	return nil
}

func daemonStop(ctx context.Context) error {
	socketPath, err := ipc.DefaultSocketPath()
	if err != nil {
		return err
	}

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client, err := ipc.NewClient(dialCtx, socketPath)
	if err != nil {
		return errors.New("aegisboxd is not running")
	}
	defer client.Close()

	if _, err := client.Authenticate(dialCtx, version.Version); err != nil {
		return fmt.Errorf("failed to authenticate with daemon: %w", err)
	}

	fmt.Println("Sent shutdown signal to aegisboxd.")
	return nil
}
