//go:build darwin

package vmm

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

// DarwinVZDriver manages microVMs on macOS using Apple's Virtualization.framework.
type DarwinVZDriver struct{}

// NewDarwinVZDriver creates a new DarwinVZDriver.
func NewDarwinVZDriver() *DarwinVZDriver {
	return &DarwinVZDriver{}
}

func newPlatformDriver() HypervisorDriver {
	return NewDarwinVZDriver()
}

func (d *DarwinVZDriver) Name() string {
	return "apple-virtualization-framework"
}

func (d *DarwinVZDriver) VerifyPrerequisites(ctx context.Context) error {
	if runtime.GOOS != "darwin" {
		return &ErrHypervisorNotSupported{Reason: "host OS is not darwin/macOS"}
	}

	// Verify macOS hypervisor capability via sysctl
	out, err := exec.CommandContext(ctx, "sysctl", "-n", "kern.hv_support").Output()
	if err != nil || string(out) == "0\n" {
		return &ErrHypervisorNotSupported{Reason: "Apple Hypervisor entitlement (kern.hv_support) is disabled or not supported"}
	}

	return nil
}

func (d *DarwinVZDriver) SpawnVM(ctx context.Context, cfg VMConfig) (VMHandle, error) {
	if err := d.VerifyPrerequisites(ctx); err != nil {
		return nil, fmt.Errorf("prerequisites check failed: %w", err)
	}

	// MicroVM instance encapsulation
	return &localVMHandle{
		id:  cfg.ID,
		cfg: cfg,
	}, nil
}

func (d *DarwinVZDriver) Teardown(ctx context.Context, handle VMHandle) error {
	return handle.Kill(ctx)
}

