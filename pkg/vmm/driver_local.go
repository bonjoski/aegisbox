package vmm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// LocalProcessDriver provides degraded host-OS process containment (Seatbelt / Airlock / bwrap)
// when explicitly authorized via --allow-degraded-local or in unit tests.
type LocalProcessDriver struct{}

// NewLocalProcessDriver returns a new LocalProcessDriver.
func NewLocalProcessDriver() *LocalProcessDriver {
	return &LocalProcessDriver{}
}

func (d *LocalProcessDriver) Name() string {
	return "local-process-driver"
}

func (d *LocalProcessDriver) VerifyPrerequisites(ctx context.Context) error {
	return VerifyLocalSandboxPrerequisites()
}

type localVMHandle struct {
	id     string
	cfg    VMConfig
	mu     sync.Mutex
	killed bool
}

func (d *LocalProcessDriver) SpawnVM(ctx context.Context, cfg VMConfig) (VMHandle, error) {
	if err := VerifyLocalSandboxPrerequisites(); err != nil {
		return nil, fmt.Errorf("degraded local sandbox prerequisites failed: %w", err)
	}
	return &localVMHandle{
		id:  cfg.ID,
		cfg: cfg,
	}, nil
}

func (d *LocalProcessDriver) Teardown(ctx context.Context, handle VMHandle) error {
	return handle.Kill(ctx)
}

func (h *localVMHandle) ID() string {
	return h.id
}

// SetWorkspaceMount updates the workspace mount for a pooled VM handle under lock.
func (h *localVMHandle) SetWorkspaceMount(path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.killed {
		return errors.New("cannot set workspace mount on terminated VM handle")
	}
	h.cfg.WorkspaceMount = path
	return nil
}

// WorkspaceMount returns the currently configured workspace mount path safely.
func (h *localVMHandle) WorkspaceMount() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg.WorkspaceMount
}

func (h *localVMHandle) snapshotConfig() VMConfig {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cfg
}

func (h *localVMHandle) VSockStream(ctx context.Context, port uint32) (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("vsock not supported on local process driver")
}

func (h *localVMHandle) Kill(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.killed = true
	return nil
}

func (h *localVMHandle) Wait(ctx context.Context) (*ProcessExitStatus, error) {
	return &ProcessExitStatus{
		ExitCode: 0,
		Duration: 10 * time.Millisecond,
	}, nil
}

// ExecuteInSandbox runs a shell command string inside the isolated shadow workspace.
func (h *localVMHandle) ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error) {
	return h.ExecuteArgvInSandbox(ctx, []string{"/bin/sh", "-c", cmdStr}, env)
}

// ExecuteArgvInSandbox runs structured argv directly inside the isolated shadow workspace without shell string flattening.
func (h *localVMHandle) ExecuteArgvInSandbox(ctx context.Context, argv []string, env []string) (string, string, int, error) {
	cfg := h.snapshotConfig()
	if len(argv) == 0 {
		return "", "", -1, errors.New("empty argv for sandboxed execution")
	}

	cmd, err := WrapArgvWithSeatbelt(ctx, argv, cfg.WorkspaceMount, cfg.Airgap)
	if err != nil {
		return "", "", -1, fmt.Errorf("sandbox confinement setup failed: %w", err)
	}
	cmd.Dir = cfg.WorkspaceMount

	tmpDir := filepath.Join(cfg.WorkspaceMount, "tmp")
	if cfg.WorkspaceMount != "" {
		if mkErr := os.MkdirAll(tmpDir, 0700); mkErr != nil {
			return "", "", -1, fmt.Errorf("failed to create sandbox scratch dir: %w", mkErr)
		}
	}

	// Strip out sensitive host env vars, pass safe ones + custom synthetic ones
	cmd.Env = append([]string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
		"HOME=" + cfg.WorkspaceMount,
		"TMPDIR=" + tmpDir,
		"AEGISBOX_SANDBOX_ACTIVE=1",
	}, env...)

	cmd.Stdin = os.Stdin

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return stdout.String(), stderr.String(), exitCode, runErr
}

// ExecuteInteractive runs an interactive command string with host terminal TTY attached.
func (h *localVMHandle) ExecuteInteractive(ctx context.Context, cmdStr string, env []string) (int, error) {
	return h.ExecuteArgvInteractive(ctx, []string{"/bin/sh", "-c", cmdStr}, env)
}

// ExecuteArgvInteractive runs structured argv interactively with host terminal TTY attached.
func (h *localVMHandle) ExecuteArgvInteractive(ctx context.Context, argv []string, env []string) (int, error) {
	cfg := h.snapshotConfig()
	if len(argv) == 0 {
		return -1, errors.New("empty argv for interactive sandboxed execution")
	}

	cmd, err := WrapArgvWithSeatbelt(ctx, argv, cfg.WorkspaceMount, cfg.Airgap)
	if err != nil {
		return -1, fmt.Errorf("sandbox confinement setup failed: %w", err)
	}
	cmd.Dir = cfg.WorkspaceMount

	tmpDir := filepath.Join(cfg.WorkspaceMount, "tmp")
	if cfg.WorkspaceMount != "" {
		if mkErr := os.MkdirAll(tmpDir, 0700); mkErr != nil {
			return -1, fmt.Errorf("failed to create sandbox scratch dir: %w", mkErr)
		}
	}

	// Strip out sensitive host env vars, pass safe ones + custom synthetic ones
	cmd.Env = append([]string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
		"HOME=" + cfg.WorkspaceMount,
		"TMPDIR=" + tmpDir,
		"AEGISBOX_SANDBOX_ACTIVE=1",
	}, env...)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return exitCode, runErr
}
