//go:build linux

package vmm

import (
	"context"
	"fmt"
	"os"
	"runtime"
)

// LinuxKVMDriver manages microVMs on Linux using KVM and Firecracker.
type LinuxKVMDriver struct{}

// NewLinuxKVMDriver creates a new LinuxKVMDriver.
func NewLinuxKVMDriver() *LinuxKVMDriver {
	return &LinuxKVMDriver{}
}

func newPlatformDriver() HypervisorDriver {
	return NewLinuxKVMDriver()
}

func (d *LinuxKVMDriver) Name() string {
	return "linux-kvm-firecracker"
}

func (d *LinuxKVMDriver) VerifyPrerequisites(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return &ErrHypervisorNotSupported{Reason: "host OS is not linux"}
	}

	// Verify /dev/kvm accessibility
	if _, err := os.Stat("/dev/kvm"); err != nil {
		return &ErrHypervisorNotSupported{Reason: "/dev/kvm is not accessible or KVM is disabled"}
	}

	return nil
}

func (d *LinuxKVMDriver) SpawnVM(ctx context.Context, cfg VMConfig) (VMHandle, error) {
	if err := d.VerifyPrerequisites(ctx); err != nil {
		return nil, fmt.Errorf("prerequisites check failed: %w", err)
	}

	return &localVMHandle{
		id:  cfg.ID,
		cfg: cfg,
	}, nil
}

func (d *LinuxKVMDriver) Teardown(ctx context.Context, handle VMHandle) error {
	return handle.Kill(ctx)
}

