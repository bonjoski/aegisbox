package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestRenderDashboard_Output(t *testing.T) {
	state := MonitorState{
		SessionID:     "sess-test-9999",
		Engine:        "apple-virtualization-framework",
		Status:        "PINNED",
		WorkspaceDir:  "/tmp/aegisbox-sess-test-9999",
		MemoryUsedMB:  128,
		MemoryLimitMB: 512,
		PIDCount:      14,
		PIDLimit:      64,
		PinnedHost:    "10.200.5.42:443",
		CanaryIPs:     []string{"169.254.169.254", "10.99.99.99"},
		CanaryTripped: false,
		Events: []SecurityEvent{
			{Timestamp: time.Now(), Level: "PASS", Message: "Pre-flight AST gate passed"},
			{Timestamp: time.Now(), Level: "INFO", Message: "Mounted shadow workspace with synthetic credentials"},
			{Timestamp: time.Now(), Level: "WARN", Message: "Attempted egress outside pinned target: blocked"},
		},
	}

	var buf bytes.Buffer
	RenderDashboard(&buf, state)
	output := buf.String()

	if !strings.Contains(output, "sess-test-9999") {
		t.Errorf("expected output to contain session ID")
	}
	if !strings.Contains(output, "10.200.5.42:443") {
		t.Errorf("expected output to contain pinned target")
	}
	if !strings.Contains(output, "169.254.169.254") {
		t.Errorf("expected output to contain canary trap IP")
	}
	if !strings.Contains(output, "Pre-flight AST gate passed") {
		t.Errorf("expected output to contain logged security event")
	}
}
