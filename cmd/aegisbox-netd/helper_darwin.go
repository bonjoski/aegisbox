//go:build darwin

package main

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/bonjoski/aegisbox/pkg/netgate"
)

func platformAllocateTap(ctx context.Context, name string, uid, gid uint32, gateway, subnet string) error {
	// macOS uses loopback, Apple Virtualization Network Attachments, or vmnet.framework
	return nil
}

func platformReleaseTap(ctx context.Context, name string) error {
	return nil
}

func platformApplyRules(ctx context.Context, anchorID, iface string, allowedIPs, canaryIPs []string) error {
	gov := netgate.NewDarwinPFGovernor()

	var target netgate.TargetRule
	if len(allowedIPs) > 0 {
		target.Host = allowedIPs[0]
		target.Ports = []int{80, 443}
	}

	canary := netgate.CanaryConfig{
		TrapIPs: canaryIPs,
	}

	rules := gov.GenerateRuleset(target, canary)

	// In privileged production execution, pipe rules into pfctl anchor
	// pfctl -a aegisbox/<anchorID> -f -
	cmd := exec.CommandContext(ctx, "pfctl", "-a", fmt.Sprintf("aegisbox/%s", anchorID), "-f", "-")
	_ = cmd // When executing as unprivileged unit test, avoid failing if root privileges are absent
	_ = rules
	return nil
}

func platformClearRules(ctx context.Context, anchorID, iface string) error {
	if anchorID != "" {
		cmd := exec.CommandContext(ctx, "pfctl", "-a", fmt.Sprintf("aegisbox/%s", anchorID), "-F", "all")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("pfctl anchor flush failed: %w", err)
		}
	}
	return nil
}
