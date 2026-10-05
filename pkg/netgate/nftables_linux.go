//go:build linux

package netgate

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

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
	tableName := fmt.Sprintf("aegisbox_%s", vmID)

	sb.WriteString(fmt.Sprintf("table inet %s {\n", tableName))
	sb.WriteString("  chain output {\n")
	sb.WriteString("    type filter hook output priority 0; policy drop;\n")
	sb.WriteString("    oif \"lo\" accept\n")
	sb.WriteString("    ct state established,related accept\n")

	// Canary Traps
	for _, trapIP := range canary.TrapIPs {
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
		if len(target.Ports) > 0 {
			var portStrs []string
			for _, p := range target.Ports {
				portStrs = append(portStrs, fmt.Sprintf("%d", p))
			}
			portsSpec := strings.Join(portStrs, ", ")
			sb.WriteString(fmt.Sprintf("    ip daddr %s %s dport { %s } accept\n", target.Host, target.Protocol, portsSpec))
		} else {
			sb.WriteString(fmt.Sprintf("    ip daddr %s %s accept\n", target.Host, target.Protocol))
		}
	}

	sb.WriteString("  }\n")
	sb.WriteString("}\n")

	return sb.String()
}

func (g *LinuxNFTGovernor) ApplyPinning(ctx context.Context, vmID string, target TargetRule, canary CanaryConfig) error {
	g.canary = canary
	ruleset := g.GenerateRuleset(vmID, target, canary)

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf

	if err := cmd.Run(); err != nil {
		if strings.Contains(errBuf.String(), "Permission denied") || strings.Contains(errBuf.String(), "Operation not permitted") {
			return nil
		}
		return fmt.Errorf("nftables apply failed: %s (%w)", errBuf.String(), err)
	}

	return nil
}

func (g *LinuxNFTGovernor) RevokePinning(ctx context.Context, vmID string) error {
	tableName := fmt.Sprintf("aegisbox_%s", vmID)
	cmd := exec.CommandContext(ctx, "nft", "delete", "table", "inet", tableName)

	if err := cmd.Run(); err != nil {
		// Non-fatal if table was already deleted or unprivileged
		return nil
	}
	return nil
}


func (g *LinuxNFTGovernor) CanaryAlertChan() <-chan string {
	return g.alerts
}

func newPlatformGovernor() NetworkGovernor {
	return NewLinuxNFTGovernor()
}
