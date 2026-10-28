package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// DefaultArgusSocket returns the canonical path to the Argus telemetry socket.
func DefaultArgusSocket() string {
	if s := os.Getenv("ARGUS_SOCKET"); s != "" {
		return s
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".argus", "argus.sock")
	}
	return filepath.Join(os.TempDir(), "argus.sock")
}

// ArgusListener listens on the Argus telemetry socket and ingests external
// telemetry events (from Airlock, Fabrial, or external agents) into the Aegisbox telemetry pipeline.
type ArgusListener struct {
	socketPath string
	listener   net.Listener
	stopCh     chan struct{}
	wg         sync.WaitGroup
	mu         sync.Mutex
	running    bool
	onEvent    func(TelemetryEvent)
}

// NewArgusListener creates an ArgusListener.
func NewArgusListener(socketPath string, onEvent func(TelemetryEvent)) *ArgusListener {
	if socketPath == "" {
		socketPath = DefaultArgusSocket()
	}
	if onEvent == nil {
		onEvent = Emit
	}
	return &ArgusListener{
		socketPath: socketPath,
		stopCh:     make(chan struct{}),
		onEvent:    onEvent,
	}
}

// Start launches the socket listener loop.
func (l *ArgusListener) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.running {
		return nil
	}

	network := "unix"
	listenAddr := l.socketPath
	if runtime.GOOS == "windows" {
		network = "tcp"
		listenAddr = "127.0.0.1:0" // Loopback fallback on Windows
	} else {
		_ = os.MkdirAll(filepath.Dir(listenAddr), 0700)
		_ = os.Remove(listenAddr) // Clean stale socket
	}

	ln, err := net.Listen(network, listenAddr)
	if err != nil {
		return fmt.Errorf("argus listener: failed to listen on %s (%s): %w", network, listenAddr, err)
	}

	l.listener = ln
	l.running = true

	l.wg.Add(1)
	go l.acceptLoop()

	return nil
}

// Addr returns the listener's network address.
func (l *ArgusListener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listener != nil {
		return l.listener.Addr()
	}
	return nil
}

func (l *ArgusListener) acceptLoop() {
	defer l.wg.Done()

	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.stopCh:
				return
			default:
				return
			}
		}

		l.wg.Add(1)
		go func(c net.Conn) {
			defer l.wg.Done()
			defer c.Close()
			l.handleConnection(c)
		}(conn)
	}
}

func (l *ArgusListener) handleConnection(conn net.Conn) {
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}

		// Handle enveloped telemetry_ingest format from Airlock ArgusStreamLogger
		var target map[string]any = raw
		if action, ok := raw["action"].(string); ok && action == "telemetry_ingest" {
			if nested, ok := raw["telemetry"].(map[string]any); ok {
				target = nested
			}
		}

		ev := l.normalizeEvent(target)
		if l.onEvent != nil {
			l.onEvent(ev)
		}
	}
}

func (l *ArgusListener) normalizeEvent(m map[string]any) TelemetryEvent {
	source, _ := m["source"].(string)
	if source == "" {
		source = "argus-external"
	}

	eventType, _ := m["event_type"].(string)
	severityStr, _ := m["severity"].(string)
	severity := SeverityNormal
	switch severityStr {
	case "WARNING", "WARN":
		severity = SeverityWarning
	case "CRITICAL", "ERROR", "HIGH":
		severity = SeverityCritical
	}

	msg := fmt.Sprintf("[%s] %s", source, eventType)
	if details, ok := m["details"].(map[string]any); ok {
		if cmd, ok := details["command"].(string); ok && cmd != "" {
			msg = fmt.Sprintf("[%s] %s: %s", source, eventType, cmd)
		}
	}

	return TelemetryEvent{
		TimestampNs: time.Now().UnixNano(),
		VMID:        source,
		Category:    "audit",
		Severity:    severity,
		Message:     msg,
		Payload:     m,
	}
}

// Stop gracefully shuts down the listener and active connections.
func (l *ArgusListener) Stop(ctx context.Context) error {
	l.mu.Lock()
	if !l.running {
		l.mu.Unlock()
		return nil
	}
	l.running = false
	close(l.stopCh)
	if l.listener != nil {
		_ = l.listener.Close()
	}
	if runtime.GOOS != "windows" {
		_ = os.Remove(l.socketPath)
	}
	l.mu.Unlock()

	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
