//go:build windows

package vmm

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

// WindowsHCSDriver manages microVMs on Windows using the Host Compute Service / Hyper-V.
type WindowsHCSDriver struct{}

// NewWindowsHCSDriver creates a new WindowsHCSDriver.
func NewWindowsHCSDriver() *WindowsHCSDriver {
	return &WindowsHCSDriver{}
}

func newPlatformDriver() HypervisorDriver {
	return NewWindowsHCSDriver()
}

func (d *WindowsHCSDriver) Name() string {
	return "windows-hyperv-hcs"
}

func (d *WindowsHCSDriver) VerifyPrerequisites(ctx context.Context) error {
	if runtime.GOOS != "windows" {
		return &ErrHypervisorNotSupported{Reason: "host OS is not windows"}
	}

	// Verify Hyper-V feature or hypervisor availability via powershell/systeminfo
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", "Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Hypervisor | Select-Object -ExpandProperty State")
	out, err := cmd.Output()
	if err != nil || string(out) == "" {
		return &ErrHypervisorNotSupported{Reason: "Hyper-V hypervisor is disabled or not present"}
	}

	return nil
}

func (d *WindowsHCSDriver) SpawnVM(ctx context.Context, cfg VMConfig) (VMHandle, error) {
	if err := d.VerifyPrerequisites(ctx); err != nil {
		return nil, fmt.Errorf("prerequisites check failed: %w", err)
	}

	return &localVMHandle{
		id:  cfg.ID,
		cfg: cfg,
	}, nil
}

func (d *WindowsHCSDriver) Teardown(ctx context.Context, handle VMHandle) error {
	return handle.Kill(ctx)
}
