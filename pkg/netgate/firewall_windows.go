//go:build windows

package netgate

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// WindowsWPFGovernor manages ephemeral Windows Firewall and WFP rulesets.
type WindowsWPFGovernor struct {
	canary CanaryConfig
	alerts chan string
}

// NewWindowsWPFGovernor creates a new governor for Windows.
func NewWindowsWPFGovernor() *WindowsWPFGovernor {
	return &WindowsWPFGovernor{
		alerts: make(chan string, 10),
	}
}

func (g *WindowsWPFGovernor) Name() string {
	return "windows-wfp-governor"
}

func (g *WindowsWPFGovernor) ApplyPinning(ctx context.Context, vmID string, target TargetRule, canary CanaryConfig) error {
	g.canary = canary
	ruleName := fmt.Sprintf("Aegisbox_Pinning_%s", vmID)

	var portStr string
	if len(target.Ports) > 0 {
		var pList []string
		for _, p := range target.Ports {
			pList = append(pList, strconv.Itoa(p))
		}
		portStr = strings.Join(pList, ",")
	}

	psScript := fmt.Sprintf(`
		New-NetFirewallRule -DisplayName "%s" -Direction Outbound -Action Allow -RemoteAddress "%s" -Protocol %s %s -ErrorAction SilentlyContinue
	`, ruleName, target.Host, target.Protocol, func() string {
		if portStr != "" {
			return fmt.Sprintf(`-RemotePort %s`, portStr)
		}
		return ""
	}())

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psScript)
	if err := cmd.Run(); err != nil {
		// Non-fatal if unprivileged
		return nil
	}

	return nil
}

func (g *WindowsWPFGovernor) RevokePinning(ctx context.Context, vmID string) error {
	ruleName := fmt.Sprintf("Aegisbox_Pinning_%s", vmID)
	psScript := fmt.Sprintf(`Remove-NetFirewallRule -DisplayName "%s" -ErrorAction SilentlyContinue`, ruleName)

	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", psScript)
	if err := cmd.Run(); err != nil {
		// Non-fatal if rule was already removed or unprivileged
		return nil
	}
	return nil
}


func (g *WindowsWPFGovernor) CanaryAlertChan() <-chan string {
	return g.alerts
}

func newPlatformGovernor() NetworkGovernor {
	return NewWindowsWPFGovernor()
}
