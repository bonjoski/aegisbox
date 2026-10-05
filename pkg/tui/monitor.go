package tui

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// SecurityEvent represents a telemetry event recorded during sandboxed execution.
type SecurityEvent struct {
	Timestamp time.Time
	Level     string // "INFO", "WARN", "CRIT", "PASS"
	Message   string
}

// MonitorState holds the live telemetry data for an active Aegisbox sandbox.
type MonitorState struct {
	SessionID     string
	Engine        string
	Status        string // "RUNNING", "IDLE", "PINNED", "KILLED"
	WorkspaceDir  string
	MemoryUsedMB  int
	MemoryLimitMB int
	PIDCount      int
	PIDLimit      int
	PinnedHost    string
	CanaryIPs     []string
	CanaryTripped bool
	Events        []SecurityEvent
}

// RenderDashboard renders a comprehensive ANSI security dashboard to the provided writer.
func RenderDashboard(w io.Writer, state MonitorState) {
	fmt.Fprintln(w, "====================================================================================================")
	fmt.Fprintln(w, "🛡️  AEGISBOX REAL-TIME SECURITY & MICROVM MONITOR")
	fmt.Fprintln(w, "====================================================================================================")

	// Status line
	statusColor := "32" // Green
	if state.Status == "KILLED" || state.CanaryTripped {
		statusColor = "31" // Red
	} else if state.Status == "PINNED" {
		statusColor = "33" // Yellow
	}

	fmt.Fprintf(w, "Session ID:    \033[1m%-18s\033[0m   Status: \033[%sm[%s]\033[0m   Engine: \033[36m%s\033[0m\n",
		state.SessionID, statusColor, state.Status, state.Engine)
	if state.WorkspaceDir != "" {
		fmt.Fprintf(w, "Workspace:     %s\n", state.WorkspaceDir)
	}
	fmt.Fprintln(w, "----------------------------------------------------------------------------------------------------")

	// Resource Gauges
	memBar := renderProgressBar(state.MemoryUsedMB, state.MemoryLimitMB, 24)
	pidBar := renderProgressBar(state.PIDCount, state.PIDLimit, 24)

	fmt.Fprintf(w, "💾 Memory: [%s] %3dMB / %3dMB      ⚡ PIDs: [%s] %3d / %3d\n",
		memBar, state.MemoryUsedMB, state.MemoryLimitMB,
		pidBar, state.PIDCount, state.PIDLimit)

	fmt.Fprintln(w, "----------------------------------------------------------------------------------------------------")

	// Network Gateway & Canaries
	pinnedStr := state.PinnedHost
	if pinnedStr == "" {
		pinnedStr = "UNPINNED (Localhost / Ephemeral only)"
	}
	canaryStr := strings.Join(state.CanaryIPs, ", ")
	if canaryStr == "" {
		canaryStr = "None"
	}

	tripwireStatus := "\033[32mARMED (No Trips)\033[0m"
	if state.CanaryTripped {
		tripwireStatus = "\033[31;1m🚨 TRIPPED - INSTANT KILL TRIGGERED\033[0m"
	}

	fmt.Fprintf(w, "🌐 Pinned Target:   \033[1m%s\033[0m\n", pinnedStr)
	fmt.Fprintf(w, "🚨 Canary Traps:    %s\n", canaryStr)
	fmt.Fprintf(w, "⚡ Tripwire State:  %s\n", tripwireStatus)
	fmt.Fprintln(w, "----------------------------------------------------------------------------------------------------")

	// Event Log
	fmt.Fprintln(w, "📜 LIVE SECURITY AUDIT LOG (Most Recent Events):")
	if len(state.Events) == 0 {
		fmt.Fprintln(w, "   [No security events recorded yet]")
	} else {
		maxEvents := 6
		startIdx := 0
		if len(state.Events) > maxEvents {
			startIdx = len(state.Events) - maxEvents
		}
		for _, ev := range state.Events[startIdx:] {
			timeStr := ev.Timestamp.Format("15:04:05.000")
			lvlColor := "37"
			icon := "ℹ️ "
			switch ev.Level {
			case "PASS":
				lvlColor = "32"
				icon = "✅"
			case "WARN":
				lvlColor = "33"
				icon = "⚠️ "
			case "CRIT":
				lvlColor = "31"
				icon = "🚨"
			}
			fmt.Fprintf(w, "   [%s] %s \033[%sm%-4s\033[0m %s\n", timeStr, icon, lvlColor, ev.Level, ev.Message)
		}
	}
	fmt.Fprintln(w, "====================================================================================================")
}

func renderProgressBar(current, total, width int) string {
	if total <= 0 {
		return strings.Repeat("░", width)
	}
	pct := float64(current) / float64(total)
	if pct > 1.0 {
		pct = 1.0
	}
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	empty := width - filled
	return strings.Repeat("█", filled) + strings.Repeat("░", empty)
}
