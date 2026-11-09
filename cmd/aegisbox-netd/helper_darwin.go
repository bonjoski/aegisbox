//go:build darwin

package main

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/netgate"
)

var reValidHelperAnchorID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func platformAllocateTap(ctx context.Context, name string, uid, gid uint32, gateway, subnet string) error {
	// macOS uses loopback, Apple Virtualization Network Attachments, or vmnet.framework
	return nil
}

func platformReleaseTap(ctx context.Context, name string) error {
	return nil
}

func platformApplyRules(ctx context.Context, anchorID, iface string, allowedIPs, canaryIPs []string) error {
	if !reValidHelperAnchorID.MatchString(anchorID) {
		return fmt.Errorf("invalid anchor ID %q", anchorID)
	}

	gov := netgate.NewDarwinPFGovernor()

	var target netgate.TargetRule
	if len(allowedIPs) > 0 {
		target.Host = allowedIPs[0]
		target.Ports = []int{80, 443}
		target.Protocol = "tcp"
	} else {
		target.Airgap = true
		target.BlockDNS = true
	}

	canary := netgate.CanaryConfig{
		TrapIPs: canaryIPs,
	}

	rules := gov.GenerateRuleset(target, canary)

	// 1. Strictly validate pfctl ruleset syntax before kernel anchor load
	if err := gov.ValidateRulesetSyntax(ctx, rules); err != nil {
		return err
	}

	// 2. Load validated rules into kernel pf anchor (fail closed on missing privileges or error)
	var errBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, "pfctl", "-a", fmt.Sprintf("aegisbox/%s", anchorID), "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pfctl anchor load failed (%s): %w", strings.TrimSpace(errBuf.String()), err)
	}
	return nil
}

func platformClearRules(ctx context.Context, anchorID, iface string) error {
	if anchorID != "" {
		if !reValidHelperAnchorID.MatchString(anchorID) {
			return fmt.Errorf("invalid anchor ID %q", anchorID)
		}
		var errBuf bytes.Buffer
		cmd := exec.CommandContext(ctx, "pfctl", "-a", fmt.Sprintf("aegisbox/%s", anchorID), "-F", "all")
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("pfctl anchor flush failed (%s): %w", strings.TrimSpace(errBuf.String()), err)
		}
	}
	return nil
}
