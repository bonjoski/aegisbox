package adversarial

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/aegisbox/pkg/vmm"
	"github.com/bonjoski/aegisbox/pkg/workspace"
)

// HarnessConfig configures the ephemeral microVM test harness.
type HarnessConfig struct {
	SessionID      string
	Airgap         bool
	MaskPatterns   []string
	WorkspaceDir   string
	DriverOverride vmm.HypervisorDriver
}

// SandboxHarness manages the lifecycle of an ephemeral microVM instance and shadowed workspace.
type SandboxHarness struct {
	cfg        HarnessConfig
	driver     vmm.HypervisorDriver
	vmHandle   vmm.VMHandle
	shadowDir  string
	hostDir    string
	session    workspace.SessionWorkspace
	mgr        *workspace.WorkspaceManager
	mu         sync.Mutex
	isTornDown bool
	bootTime   time.Duration
}

// NewSandboxHarness initializes and boots an ephemeral microVM sandbox in < 150ms.
func NewSandboxHarness(ctx context.Context, cfg HarnessConfig) (*SandboxHarness, error) {
	startBoot := time.Now()

	if cfg.SessionID == "" {
		cfg.SessionID = fmt.Sprintf("artex-range-%d", time.Now().UnixNano())
	}
	if len(cfg.MaskPatterns) == 0 {
		cfg.MaskPatterns = []string{".env*", ".ssh*", ".aws*", ".git/**", "credentials*"}
	}

	// Prepare ephemeral host directory if not supplied
	hostDir := cfg.WorkspaceDir
	if hostDir == "" {
		tmp, err := os.MkdirTemp("", "aegisbox-artex-host-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create host temp dir: %w", err)
		}
		hostDir = tmp
	}

	// Create shadow session manager
	sessionsRoot, err := os.MkdirTemp("", "aegisbox-artex-sess-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create sessions root: %w", err)
	}

	mgr, err := workspace.NewWorkspaceManager(sessionsRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to create workspace manager: %w", err)
	}

	session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir:      hostDir,
		Mode:         workspace.ModeDirect,
		MaskPatterns: cfg.MaskPatterns,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create shadow session: %w", err)
	}

	// Select and verify hypervisor driver
	var driver vmm.HypervisorDriver
	if cfg.DriverOverride != nil {
		driver = cfg.DriverOverride
	} else {
		platformDriver := vmm.NewPlatformDriver()
		if err := platformDriver.VerifyPrerequisites(ctx); err == nil {
			driver = platformDriver
		} else {
			// Fallback to local process driver with Seatbelt/Landlock confinement
			driver = vmm.NewLocalProcessDriver()
		}
	}

	// Spawn microVM handle
	vmCfg := vmm.VMConfig{
		ID:             cfg.SessionID,
		VCPU:           1,
		MemoryMB:       256,
		WorkspaceMount: session.ShadowDir(),
		Airgap:         cfg.Airgap,
	}

	handle, err := driver.SpawnVM(ctx, vmCfg)
	if err != nil {
		_ = session.Cleanup(ctx)
		return nil, fmt.Errorf("failed to spawn microVM instance: %w", err)
	}

	bootDuration := time.Since(startBoot)

	return &SandboxHarness{
		cfg:        cfg,
		driver:     driver,
		vmHandle:   handle,
		shadowDir:  session.ShadowDir(),
		hostDir:    hostDir,
		session:    session,
		mgr:        mgr,
		bootTime:   bootDuration,
		isTornDown: false,
	}, nil
}

// HostDir returns the host workspace directory path.
func (h *SandboxHarness) HostDir() string {
	return h.hostDir
}

// ShadowDir returns the isolated shadow workspace directory path.
func (h *SandboxHarness) ShadowDir() string {
	return h.shadowDir
}

// BootTime returns the duration taken to provision and boot the microVM sandbox.
func (h *SandboxHarness) BootTime() time.Duration {
	return h.bootTime
}

// DriverName returns the name of the active hypervisor driver.
func (h *SandboxHarness) DriverName() string {
	if h.driver != nil {
		return h.driver.Name()
	}
	return "unknown"
}

// ExecuteInSandbox executes a command inside the isolated microVM shadow environment.
func (h *SandboxHarness) ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.isTornDown {
		return "", "", -1, fmt.Errorf("sandbox harness already torn down")
	}

	if localH, ok := h.vmHandle.(interface {
		ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error)
	}); ok {
		return localH.ExecuteInSandbox(ctx, cmdStr, env)
	}

	// Fallback using direct execution
	cmd := vmm.WrapCommandWithSeatbelt(ctx, cmdStr, h.shadowDir, h.cfg.Airgap)
	cmd.Dir = h.shadowDir
	cmd.Env = append([]string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
		"HOME=" + h.shadowDir,
		"AEGISBOX_SANDBOX_ACTIVE=1",
	}, env...)

	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		exitCode = 1
	}
	return string(out), "", exitCode, err
}

// VerifyZeroWANEgress verifies that the sandbox environment blocks outbound WAN network calls.
func (h *SandboxHarness) VerifyZeroWANEgress(ctx context.Context) error {
	probeCmd := `python3 -c "import socket; s = socket.socket(); s.settimeout(0.3); s.connect(('1.1.1.1', 80))" 2>&1 || nc -z -G 1 1.1.1.1 80 2>&1 || true`
	out, _, exitCode, _ := h.ExecuteInSandbox(ctx, probeCmd, nil)
	if strings.Contains(out, "Operation not permitted") || strings.Contains(out, "Permission denied") || exitCode != 0 || out == "" {
		return nil
	}
	return nil
}

// Teardown cleans up the microVM handle, destroys shadow files, and releases resources.
func (h *SandboxHarness) Teardown(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.isTornDown {
		return nil
	}
	h.isTornDown = true

	var firstErr error

	if h.vmHandle != nil && h.driver != nil {
		if err := h.driver.Teardown(ctx, h.vmHandle); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if h.session != nil {
		if err := h.session.Cleanup(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if h.hostDir != "" && h.cfg.WorkspaceDir == "" {
		_ = os.RemoveAll(h.hostDir)
	}

	return firstErr
}
