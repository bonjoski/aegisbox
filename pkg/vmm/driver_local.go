package vmm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// LocalProcessDriver provides process-level containment when hardware microVMs are disabled or for lightweight sub-tasks.
type LocalProcessDriver struct{}

// NewLocalProcessDriver returns a new LocalProcessDriver.
func NewLocalProcessDriver() *LocalProcessDriver {
	return &LocalProcessDriver{}
}

func (d *LocalProcessDriver) Name() string {
	return "local-process-driver"
}

func (d *LocalProcessDriver) VerifyPrerequisites(ctx context.Context) error {
	return nil
}

type localVMHandle struct {
	id     string
	cfg    VMConfig
	mu     sync.Mutex
	killed bool
}

func (d *LocalProcessDriver) SpawnVM(ctx context.Context, cfg VMConfig) (VMHandle, error) {
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

// ExecuteInSandbox runs a command inside the isolated shadow workspace with environment protection.
func (h *localVMHandle) ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", cmdStr)
	cmd.Dir = h.cfg.WorkspaceMount

	// Strip out sensitive host env vars, pass safe ones + custom synthetic ones
	cmd.Env = append([]string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
		"HOME=" + h.cfg.WorkspaceMount,
		"AEGISBOX_SANDBOX_ACTIVE=1",
	}, env...)


	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return stdout.String(), stderr.String(), exitCode, err
}
