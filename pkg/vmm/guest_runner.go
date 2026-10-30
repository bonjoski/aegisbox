package vmm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/aegisbox/pkg/bridge"
)

// GuestRunner manages an ephemeral aegisbox-guest daemon process for microVM execution.
type GuestRunner struct {
	binaryPath string
}

// NewGuestRunner creates a new GuestRunner. If binaryPath is empty, it searches PATH, executable dir, and ./bin.
func NewGuestRunner(binaryPath string) *GuestRunner {
	if binaryPath == "" {
		if execPath, err := os.Executable(); err == nil {
			sibling := filepath.Join(filepath.Dir(execPath), "aegisbox-guest")
			if _, err := os.Stat(sibling); err == nil {
				binaryPath = sibling
			}
		}
		if binaryPath == "" {
			if p, err := exec.LookPath("aegisbox-guest"); err == nil {
				binaryPath = p
			} else if abs, err := filepath.Abs("bin/aegisbox-guest"); err == nil {
				if _, err := os.Stat(abs); err == nil {
					binaryPath = abs
				}
			}
		}
	}

	if binaryPath != "" {
		if abs, err := filepath.Abs(binaryPath); err == nil {
			binaryPath = abs
		}
	}
	return &GuestRunner{binaryPath: binaryPath}
}

// GuestVMHandle represents an active guest daemon execution context.
type GuestVMHandle struct {
	id           string
	cfg          VMConfig
	cmd          *exec.Cmd
	addr         string
	sigAddr      string
	client       *VSockClient
	signalBridge *bridge.HostBridge
	mu           sync.Mutex
	killed       bool
	exitStatus   *ProcessExitStatus
}

// SpawnGuest launches the aegisbox-guest daemon bound to an ephemeral port and establishes the RPC client.
func (r *GuestRunner) SpawnGuest(ctx context.Context, cfg VMConfig) (*GuestVMHandle, error) {
	// Security fail-closed: A caller requesting microVM isolation expects hardware hypervisor boundary.
	// In production, refuse to execute unconfined on host. Mock guest daemon is only permitted in explicit test mode.
	if os.Getenv("AEGISBOX_TEST_GUEST") != "1" && os.Getenv("AEGISBOX_ALLOW_MOCK_GUEST") != "1" {
		return nil, fmt.Errorf("microvm engine failed to initialize: hardware hypervisor microVM guest is not available on this host (refusing to execute untrusted payload on host without hypervisor isolation boundary)")
	}

	if r.binaryPath == "" {
		return nil, fmt.Errorf("aegisbox-guest binary not found; please compile it first via 'go build -o bin/aegisbox-guest ./cmd/aegisbox-guest'")
	}

	// Use dynamic port (127.0.0.1:0)
	cmd := exec.CommandContext(ctx, r.binaryPath, "-addr", "127.0.0.1:0")
	if cfg.WorkspaceMount != "" {
		cmd.Dir = cfg.WorkspaceMount
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to open stdout pipe to guest daemon: %w", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start guest daemon: %w", err)
	}

	// Read listening address from daemon's startup banner
	addrChan := make(chan string, 1)
	sigAddrChan := make(chan string, 1)
	errChan := make(chan error, 1)

	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			// e.g.: "✅ Guest signal bridge listening on 127.0.0.1:54322 (Port 0x5161)"
			if strings.Contains(line, "signal bridge listening on") {
				parts := strings.Split(line, "signal bridge listening on")
				if len(parts) > 1 {
					sigAddr := strings.TrimSpace(strings.Fields(parts[1])[0])
					select {
					case sigAddrChan <- sigAddr:
					default:
					}
				}
			} else if strings.Contains(line, "listening on") {
				// e.g.: "✅ Guest daemon listening on 127.0.0.1:54321"
				parts := strings.Split(line, "listening on")
				if len(parts) > 1 {
					addr := strings.TrimSpace(strings.Fields(parts[1])[0])
					select {
					case addrChan <- addr:
					default:
					}
				}
			}
		}
		if err := scanner.Err(); err != nil {
			errChan <- err
		}
	}()

	var boundAddr string
	select {
	case boundAddr = <-addrChan:
	case err := <-errChan:
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("guest daemon startup failed: %w", err)
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("timed out waiting for guest daemon to bind")
	}

	var sigAddr string
	select {
	case sigAddr = <-sigAddrChan:
	case <-time.After(500 * time.Millisecond):
		// Optional if guest runs without signal bridge
	}

	client := NewVSockClient(boundAddr, 30*time.Second)

	return &GuestVMHandle{
		id:      cfg.ID,
		cfg:     cfg,
		cmd:     cmd,
		addr:    boundAddr,
		sigAddr: sigAddr,
		client:  client,
	}, nil
}

func (h *GuestVMHandle) ID() string {
	return h.id
}

// SignalBridge returns the active host signal forwarder if enabled.
func (h *GuestVMHandle) SignalBridge() *bridge.HostBridge {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.signalBridge
}

// EnableSignalBridge dials the guest's vsock signal endpoint (port 0x5161)
// and starts host signal trapping and keepalive heartbeats.
func (h *GuestVMHandle) EnableSignalBridge(ctx context.Context) (*bridge.HostBridge, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.signalBridge != nil {
		return h.signalBridge, nil
	}
	if h.sigAddr == "" {
		return nil, fmt.Errorf("guest did not report a signal bridge endpoint")
	}

	hb, err := bridge.DialHostBridge(ctx, "tcp", h.sigAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to guest vsock signal bridge at %s: %w", h.sigAddr, err)
	}

	hb.StartSignalTrap()
	hb.StartHeartbeat(bridge.DefaultHeartbeatInterval)
	h.signalBridge = hb
	return hb, nil
}

func (h *GuestVMHandle) VSockStream(ctx context.Context, port uint32) (io.ReadWriteCloser, error) {
	var d net.Dialer
	return d.DialContext(ctx, "tcp", h.addr)
}

func (h *GuestVMHandle) ExecuteInGuest(ctx context.Context, cmdStr string, env map[string]string) (*ExecutionResult, error) {
	req := ExecutionRequest{
		Command: cmdStr,
		Env:     env,
		WorkDir: h.cfg.WorkspaceMount,
		Timeout: h.cfg.Timeout,
	}
	return h.client.Execute(ctx, req)
}

func (h *GuestVMHandle) Kill(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.killed {
		return nil
	}
	h.killed = true
	if h.signalBridge != nil {
		_ = h.signalBridge.Close()
	}
	if h.cmd != nil && h.cmd.Process != nil {
		return h.cmd.Process.Kill()
	}
	return nil
}

func (h *GuestVMHandle) Wait(ctx context.Context) (*ProcessExitStatus, error) {
	h.mu.Lock()
	if h.exitStatus != nil {
		defer h.mu.Unlock()
		return h.exitStatus, nil
	}
	h.mu.Unlock()

	start := time.Now()
	err := h.cmd.Wait()
	duration := time.Since(start)

	status := &ProcessExitStatus{
		ExitCode: 0,
		Duration: duration,
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			status.ExitCode = exitErr.ExitCode()
		} else {
			status.ExitCode = -1
			status.ErrorMsg = err.Error()
		}
	}

	h.mu.Lock()
	h.exitStatus = status
	h.mu.Unlock()

	return status, nil
}
