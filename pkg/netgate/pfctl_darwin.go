//go:build darwin

package netgate

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var reValidAnchorID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// DarwinPFGovernor manages ephemeral pfctl anchor rules on macOS.
type DarwinPFGovernor struct {
	canary CanaryConfig
	alerts chan string
}

// NewDarwinPFGovernor creates a new pfctl governor for macOS.
func NewDarwinPFGovernor() *DarwinPFGovernor {
	return &DarwinPFGovernor{
		alerts: make(chan string, 10),
	}
}

func (g *DarwinPFGovernor) Name() string {
	return "darwin-pfctl-governor"
}

// GenerateRuleset synthesizes a strict packet filter ruleset for an isolated VM / range session.
func (g *DarwinPFGovernor) GenerateRuleset(target TargetRule, canary CanaryConfig) string {
	var sb strings.Builder
	sb.WriteString("# Ephemeral Aegisbox Host Pinning Anchor\n")

	// 1. Drop all traffic by default from sandboxed interface/session
	sb.WriteString("block drop out all\n")

	// 2. Allow local loopback resolution if needed
	sb.WriteString("pass on lo0 all\n")

	// 3. Canary Trap IP rules - log/trap any attempt
	for _, trapIP := range canary.TrapIPs {
		trapIP = strings.TrimSpace(trapIP)
		if trapIP != "" {
			sb.WriteString(fmt.Sprintf("block return out quick to %s\n", trapIP))
		}
	}

	// 4. DNS Blocking (Prevent DNS tunneling via UDP/TCP port 53)
	if target.Airgap || target.BlockDNS {
		sb.WriteString("block drop out quick proto { tcp, udp } to any port 53\n")
	}

	// If in Airgap mode, no outbound rules are emitted beyond loopback
	if target.Airgap {
		return sb.String()
	}

	// 5. Pass rule strictly to target host and ports
	if target.Host != "" {
		proto := strings.TrimSpace(target.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		if len(target.Ports) > 0 {
			var portStrs []string
			for _, p := range target.Ports {
				portStrs = append(portStrs, fmt.Sprintf("%d", p))
			}
			portsSpec := strings.Join(portStrs, " ")
			if len(target.Ports) > 1 {
				portsSpec = fmt.Sprintf("{ %s }", portsSpec)
			}
			sb.WriteString(fmt.Sprintf("pass out proto %s to %s port %s keep state\n", proto, target.Host, portsSpec))
		} else {
			sb.WriteString(fmt.Sprintf("pass out proto %s to %s keep state\n", proto, target.Host))
		}
	}

	return sb.String()
}

// ValidateRulesetSyntax validates pf ruleset syntax via `pfctl -nf -` without loading into kernel.
func (g *DarwinPFGovernor) ValidateRulesetSyntax(ctx context.Context, ruleset string) error {
	cmd := exec.CommandContext(ctx, "pfctl", "-nf", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pfctl ruleset syntax validation failed (%s): %w", strings.TrimSpace(errBuf.String()), err)
	}
	return nil
}

func (g *DarwinPFGovernor) ApplyPinning(ctx context.Context, vmID string, target TargetRule, canary CanaryConfig) error {
	if !reValidAnchorID.MatchString(vmID) {
		return fmt.Errorf("invalid vmID %q for pfctl anchor", vmID)
	}
	g.canary = canary
	ruleset := g.GenerateRuleset(target, canary)

	if err := g.ValidateRulesetSyntax(ctx, ruleset); err != nil {
		return err
	}

	anchorName := fmt.Sprintf("aegisbox_%s", vmID)
	cmd := exec.CommandContext(ctx, "pfctl", "-a", anchorName, "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf

	// Fail closed if pfctl lacks privileges or kernel anchor loading fails.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pfctl anchor apply failed (%s): %w", strings.TrimSpace(errBuf.String()), err)
	}

	return nil
}

func (g *DarwinPFGovernor) RevokePinning(ctx context.Context, vmID string) error {
	if !reValidAnchorID.MatchString(vmID) {
		return fmt.Errorf("invalid vmID %q for pfctl anchor", vmID)
	}
	anchorName := fmt.Sprintf("aegisbox_%s", vmID)
	var errBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, "pfctl", "-a", anchorName, "-F", "all")
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pfctl anchor flush failed (%s): %w", strings.TrimSpace(errBuf.String()), err)
	}
	return nil
}

func (g *DarwinPFGovernor) CanaryAlertChan() <-chan string {
	return g.alerts
}

func newPlatformGovernor() NetworkGovernor {
	return NewDarwinPFGovernor()
}
