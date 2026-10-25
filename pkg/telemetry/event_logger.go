package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	eventMu sync.Mutex
)

// DefaultEventsFilePath returns the path to the shared JSONL event stream.
func DefaultEventsFilePath() string {
	if runtimeDir := os.Getenv("XDG_RUNTIME_DIR"); runtimeDir != "" {
		return filepath.Join(runtimeDir, "aegisbox", "events.jsonl")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".aegisbox", "events.jsonl")
	}
	return filepath.Join(os.TempDir(), "aegisbox-events.jsonl")
}

// Emit writes a TelemetryEvent to the shared events.jsonl file.
func Emit(ev TelemetryEvent) {
	if ev.TimestampNs == 0 {
		ev.TimestampNs = time.Now().UnixNano()
	}
	if ev.Severity == "" {
		ev.Severity = SeverityNormal
	}

	path := DefaultEventsFilePath()
	eventMu.Lock()
	defer eventMu.Unlock()

	_ = os.MkdirAll(filepath.Dir(path), 0700)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	data, err := json.Marshal(ev)
	if err != nil {
		return
	}

	data = append(data, '\n')
	_, _ = f.Write(data)
}

// Log emits a standard log message.
func Log(vmID, message, category string) {
	Emit(TelemetryEvent{
		VMID:     vmID,
		Category: category,
		Severity: SeverityNormal,
		Message:  message,
	})
}

// LogTripwire emits an active security tripwire alert.
func LogTripwire(vmID, message, targetIP string) {
	Emit(TelemetryEvent{
		VMID:            vmID,
		Category:        "tripwire",
		Severity:        SeverityCritical,
		Message:         message,
		CanaryTriggered: true,
		CanaryTargetIP:  targetIP,
	})
}

// LogMCP emits an MCP tool invocation event.
func LogMCP(vmID, toolName, argsJSON, decision string) {
	Emit(TelemetryEvent{
		VMID:     vmID,
		Category: "mcp",
		Severity: SeverityNormal,
		Message:  "MCP tool call: " + toolName + " => " + decision,
		Payload: map[string]any{
			"tool_name": toolName,
			"args":      argsJSON,
			"decision":  decision,
		},
	})
}

// LogEgress emits an outbound network / DNS mediation event.
func LogEgress(vmID, domain, ip string, port int, protocol string) {
	Emit(TelemetryEvent{
		VMID:     vmID,
		Category: "egress",
		Severity: SeverityNormal,
		Message:  "Egress probe: " + domain + " (" + ip + ")",
		Payload: map[string]any{
			"domain":   domain,
			"ip":       ip,
			"port":     port,
			"protocol": protocol,
		},
	})
}
