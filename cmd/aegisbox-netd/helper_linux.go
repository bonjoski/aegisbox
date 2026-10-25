//go:build linux

package main

import (
	"context"
	"fmt"
	"os/exec"
)

func platformAllocateTap(ctx context.Context, name string, uid, gid uint32, gateway, subnet string) error {
	// Allocate TAP interface using Linux ip tuntap
	cmd := exec.CommandContext(ctx, "ip", "tuntap", "add", "mode", "tap", name, "user", fmt.Sprintf("%d", uid))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ip tuntap add failed: %w", err)
	}

	// Assign IP
	addrCmd := exec.CommandContext(ctx, "ip", "addr", "add", gateway+"/24", "dev", name)
	if err := addrCmd.Run(); err != nil {
		return fmt.Errorf("ip addr add failed: %w", err)
	}

	// Bring link up
	upCmd := exec.CommandContext(ctx, "ip", "link", "set", name, "up")
	if err := upCmd.Run(); err != nil {
		return fmt.Errorf("ip link set up failed: %w", err)
	}

	return nil
}

func platformReleaseTap(ctx context.Context, name string) error {
	cmd := exec.CommandContext(ctx, "ip", "link", "delete", name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ip link delete failed: %w", err)
	}
	return nil
}

func platformApplyRules(ctx context.Context, anchorID, iface string, allowedIPs, canaryIPs []string) error {
	// Generate nftables table for this microVM instance
	table := fmt.Sprintf("aegis_%s", anchorID)
	cmd := exec.CommandContext(ctx, "nft", "add", "table", "inet", table)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft add table failed: %w", err)
	}
	return nil
}

func platformClearRules(ctx context.Context, anchorID, iface string) error {
	if anchorID != "" {
		table := fmt.Sprintf("aegis_%s", anchorID)
		cmd := exec.CommandContext(ctx, "nft", "delete", "table", "inet", table)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("nft delete table failed: %w", err)
		}
	}
	return nil
}
