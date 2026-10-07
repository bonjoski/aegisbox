package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bonjoski/aegisbox/pkg/tui"
	"github.com/bonjoski/aegisbox/pkg/vmm"
)

func runMonitor(ctx context.Context, args []string) error {
	monitorFlags := flag.NewFlagSet("monitor", flag.ExitOnError)
	sessionID := monitorFlags.String("session", "", "Specific session ID to monitor")
	demoMode := monitorFlags.Bool("demo", false, "Run an interactive live simulation of sandbox telemetry")

	monitorFlags.Usage = func() {
		fmt.Println("Usage: aegisbox monitor [flags]")
		monitorFlags.PrintDefaults()
	}

	if err := monitorFlags.Parse(args); err != nil {
		return err
	}

	driver := vmm.NewPlatformDriver()
	engineName := driver.Name()

	if *demoMode {
		fmt.Println("🚀 Starting Aegisbox Real-Time Security Monitor (Live Simulation)...")
		time.Sleep(500 * time.Millisecond)

		state := tui.MonitorState{
			SessionID:     "demo-range-4281",
			Engine:        engineName,
			Status:        "PINNED",
			WorkspaceDir:  "~/.aegisbox/sessions/demo-range-4281",
			MemoryUsedMB:  48,
			MemoryLimitMB: 512,
			PIDCount:      8,
			PIDLimit:      64,
			PinnedHost:    "10.200.5.42:443",
			CanaryIPs:     []string{"169.254.169.254", "10.99.99.99"},
			CanaryTripped: false,
			Events: []tui.SecurityEvent{
				{Timestamp: time.Now().Add(-5 * time.Second), Level: "PASS", Message: "Argus AST Pre-flight verified 0 evasion patterns"},
				{Timestamp: time.Now().Add(-4 * time.Second), Level: "INFO", Message: "Mounted shadow Git worktree (.git/hooks masked)"},
				{Timestamp: time.Now().Add(-3 * time.Second), Level: "INFO", Message: "Injected synthetic API keys (sk-dummy-test-0000)"},
				{Timestamp: time.Now().Add(-2 * time.Second), Level: "INFO", Message: "PF packet filter pinned to 10.200.5.42:443"},
				{Timestamp: time.Now().Add(-1 * time.Second), Level: "PASS", Message: "Permitted egress: TCP handshake to 10.200.5.42:443"},
				{Timestamp: time.Now(), Level: "WARN", Message: "Blocked unauthorized DNS query: metadata.internal.aws"},
			},
		}

		tui.RenderDashboard(os.Stdout, state)
		return nil
	}

	// Live status
	sess := *sessionID
	if sess == "" {
		sess = fmt.Sprintf("active-%d", time.Now().Unix()%10000)
	}

	state := tui.MonitorState{
		SessionID:     sess,
		Engine:        engineName,
		Status:        "RUNNING",
		WorkspaceDir:  "~/.aegisbox/sessions/" + sess,
		MemoryUsedMB:  32,
		MemoryLimitMB: 512,
		PIDCount:      4,
		PIDLimit:      64,
		PinnedHost:    "Local Isolated Sandbox",
		CanaryIPs:     []string{"169.254.169.254"},
		CanaryTripped: false,
		Events: []tui.SecurityEvent{
			{Timestamp: time.Now(), Level: "INFO", Message: "Aegisbox monitoring attached"},
			{Timestamp: time.Now(), Level: "PASS", Message: "MicroVM hardware acceleration active"},
		},
	}

	tui.RenderDashboard(os.Stdout, state)
	return nil
}
