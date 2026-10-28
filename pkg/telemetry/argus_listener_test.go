package telemetry

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestArgusListener_IngestAndFanout(t *testing.T) {
	// macOS Unix domain socket paths have a 104 character maximum limit; use /tmp on Darwin
	tmpDir := os.TempDir()
	if runtime.GOOS == "darwin" {
		tmpDir = "/tmp"
	}
	f, err := os.CreateTemp(tmpDir, "argus-*.sock")
	if err != nil {
		t.Fatalf("failed to create temp socket file: %v", err)
	}
	socketPath := f.Name()
	f.Close()
	os.Remove(socketPath)
	defer os.Remove(socketPath)

	var received []TelemetryEvent
	var mu sync.Mutex

	listener := NewArgusListener(socketPath, func(ev TelemetryEvent) {
		mu.Lock()
		defer mu.Unlock()
		received = append(received, ev)
	})

	if err := listener.Start(); err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Stop(context.Background())

	// Connect client to socket
	network := listener.Addr().Network()
	addr := listener.Addr().String()

	conn, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial argus socket: %v", err)
	}
	defer conn.Close()

	// Send an event in the enveloped Airlock ArgusStreamLogger format
	payload := map[string]any{
		"action": "telemetry_ingest",
		"telemetry": map[string]any{
			"source":     "airlock",
			"event_type": "execution.completed",
			"severity":   "INFO",
			"details": map[string]any{
				"command": "npm install",
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}
	data = append(data, '\n')

	if _, err := conn.Write(data); err != nil {
		t.Fatalf("failed to write to argus socket: %v", err)
	}

	// Wait for event delivery
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(received)
		mu.Unlock()
		if count > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatalf("expected to receive normalized telemetry event, got none")
	}

	ev := received[0]
	if ev.VMID != "airlock" {
		t.Errorf("expected VMID 'airlock', got %q", ev.VMID)
	}
	if ev.Category != "audit" {
		t.Errorf("expected Category 'audit', got %q", ev.Category)
	}
	if ev.Message != "[airlock] execution.completed: npm install" {
		t.Errorf("unexpected message format: %q", ev.Message)
	}
}
