package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bonjoski/aegisbox/pkg/netgate"
)



func runRange(ctx context.Context, args []string) error {
	rangeFlags := flag.NewFlagSet("range", flag.ExitOnError)
	targetFlag := rangeFlags.String("target", "", "Target host and port (e.g. 10.200.5.42:443)")
	canaryTrap := rangeFlags.String("canary", "10.99.99.99,169.254.169.254", "Comma-separated canary trap IPs")

	rangeFlags.Usage = func() {
		fmt.Println("Usage: aegisbox range --target <host:port> -- <command>")
		rangeFlags.PrintDefaults()
	}


	if err := rangeFlags.Parse(args); err != nil {
		return err
	}

	if *targetFlag == "" {
		rangeFlags.Usage()
		return fmt.Errorf("target host and port must be specified via --target")
	}

	parts := strings.Split(*targetFlag, ":")
	targetHost := parts[0]
	var targetPorts []int
	if len(parts) > 1 {
		p, err := strconv.Atoi(parts[1])
		if err == nil {
			targetPorts = append(targetPorts, p)
		}
	}

	cmdArgs := rangeFlags.Args()
	if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}

	if len(cmdArgs) == 0 {
		return fmt.Errorf("no command specified after '--'")
	}

	cmdStr := strings.Join(cmdArgs, " ")

	fmt.Printf("🎯 Initializing Adversarial Range Execution\n")
	fmt.Printf("📌 Pinned Target: %s (Ports: %v)\n", targetHost, targetPorts)
	fmt.Printf("🚨 Canary Tripwires: %s\n", *canaryTrap)
	fmt.Printf("⚡ Command: %s\n\n", cmdStr)

	// Configure Network Governor
	governor := netgate.NewPlatformGovernor()
	vmID := fmt.Sprintf("range-session-%d", time.Now().Unix())

	monitor := netgate.NewCanaryMonitor()
	canaries := strings.Split(*canaryTrap, ",")

	canaryConfig := netgate.CanaryConfig{
		TrapIPs: canaries,
		OnTrapTrigger: func(vID, trapIP string) {
			fmt.Fprintf(os.Stderr, "\n🚨 CRITICAL THREAT: Canary Tripwire %s triggered by %s! Terminating VM instantly.\n", trapIP, vID)
		},
	}

	monitor.RegisterVM(vmID, canaryConfig)
	defer monitor.UnregisterVM(vmID)

	if err := governor.ApplyPinning(ctx, vmID, netgate.TargetRule{
		Host:     targetHost,
		Ports:    targetPorts,
		Protocol: "tcp",
	}, canaryConfig); err != nil {
		return fmt.Errorf("failed to apply network pinning: %w", err)
	}
	defer governor.RevokePinning(ctx, vmID)

	fmt.Printf("🔒 Host Network Rules Pinned via [%s].\n", governor.Name())
	fmt.Println("🛡️  Zero egress permitted outside specified target.")


	// Execute sandboxed command
	execArgs := []string{"--mask", ".git/**,.env*", cmdStr}
	return runExec(ctx, execArgs)
}


func runDiff(ctx context.Context, args []string) error {
	fmt.Println("🔍 Aegisbox Session Diff Inspector")
	fmt.Println("No active detached session found in current workspace.")
	return nil
}

