//go:build linux

package netgate

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var reValidNFTID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// LinuxNFTGovernor manages ephemeral nftables rulesets on Linux.
type LinuxNFTGovernor struct {
	canary CanaryConfig
	alerts chan string
}

// NewLinuxNFTGovernor creates a new nftables governor for Linux.
func NewLinuxNFTGovernor() *LinuxNFTGovernor {
	return &LinuxNFTGovernor{
		alerts: make(chan string, 10),
	}
}

func (g *LinuxNFTGovernor) Name() string {
	return "linux-nftables-governor"
}

// GenerateRuleset synthesizes an nftables configuration restricting egress.
func (g *LinuxNFTGovernor) GenerateRuleset(vmID string, target TargetRule, canary CanaryConfig) string {
	var sb strings.Builder
	safeID := strings.ReplaceAll(vmID, "-", "_")
	tableName := fmt.Sprintf("aegisbox_%s", safeID)

	sb.WriteString(fmt.Sprintf("table inet %s {\n", tableName))
	sb.WriteString("  chain output {\n")
	sb.WriteString("    type filter hook output priority 0; policy drop;\n")
	sb.WriteString("    oif \"lo\" accept\n")
	sb.WriteString("    ct state established,related accept\n")

	// Canary Traps
	for _, trapIP := range canary.TrapIPs {
		trapIP = strings.TrimSpace(trapIP)
		if trapIP != "" {
			sb.WriteString(fmt.Sprintf("    ip daddr %s drop\n", trapIP))
		}
	}

	// DNS Blocking
	if target.Airgap || target.BlockDNS {
		sb.WriteString("    udp dport 53 drop\n")
		sb.WriteString("    tcp dport 53 drop\n")
	}

	if target.Airgap {
		sb.WriteString("  }\n")
		sb.WriteString("}\n")
		return sb.String()
	}

	// Permitted Target Rule
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
			portsSpec := strings.Join(portStrs, ", ")
			sb.WriteString(fmt.Sprintf("    ip daddr %s %s dport { %s } accept\n", target.Host, proto, portsSpec))
		} else {
			sb.WriteString(fmt.Sprintf("    ip daddr %s %s accept\n", target.Host, proto))
		}
	}

	sb.WriteString("  }\n")
	sb.WriteString("}\n")

	return sb.String()
}

func (g *LinuxNFTGovernor) ApplyPinning(ctx context.Context, vmID string, target TargetRule, canary CanaryConfig) error {
	if !reValidNFTID.MatchString(vmID) {
		return fmt.Errorf("invalid vmID %q for nftables table", vmID)
	}
	g.canary = canary
	ruleset := g.GenerateRuleset(vmID, target, canary)

	// Validate syntax first (`nft -c -f -`), then apply (`nft -f -`) and fail closed on any error.
	checkCmd := exec.CommandContext(ctx, "nft", "-c", "-f", "-")
	checkCmd.Stdin = strings.NewReader(ruleset)
	var checkErrBuf bytes.Buffer
	checkCmd.Stderr = &checkErrBuf
	if err := checkCmd.Run(); err != nil {
		return fmt.Errorf("nftables ruleset validation failed (%s): %w", strings.TrimSpace(checkErrBuf.String()), err)
	}

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nftables apply failed (%s): %w", strings.TrimSpace(errBuf.String()), err)
	}

	return nil
}

func (g *LinuxNFTGovernor) RevokePinning(ctx context.Context, vmID string) error {
	if !reValidNFTID.MatchString(vmID) {
		return fmt.Errorf("invalid vmID %q for nftables table", vmID)
	}
	safeID := strings.ReplaceAll(vmID, "-", "_")
	tableName := fmt.Sprintf("aegisbox_%s", safeID)
	var errBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, "nft", "delete", "table", "inet", tableName)
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nftables delete table failed (%s): %w", strings.TrimSpace(errBuf.String()), err)
	}
	return nil
}

func (g *LinuxNFTGovernor) CanaryAlertChan() <-chan string {
	return g.alerts
}

func newPlatformGovernor() NetworkGovernor {
	return NewLinuxNFTGovernor()
}
