//go:build linux

package vmm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// LinuxKVMDriver manages microVMs on Linux using KVM and Firecracker / libkrun.
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

func hasLinuxMicroVMAppliance() bool {
	if os.Getenv("AEGISBOX_TEST_GUEST") == "1" || os.Getenv("AEGISBOX_ALLOW_MOCK_GUEST") == "1" {
		runner := NewGuestRunner("")
		return runner.binaryPath != ""
	}

	home, _ := os.UserHomeDir()
	applianceCandidates := []string{
		"build/appliance/appliance.squashfs",
		"appliance/appliance.squashfs",
	}
	if home != "" {
		applianceCandidates = append(applianceCandidates, filepath.Join(home, ".aegisbox", "appliance.squashfs"))
	}
	hasRootfs := false
	for _, c := range applianceCandidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			hasRootfs = true
			break
		}
	}
	if !hasRootfs {
		return false
	}

	if _, err := exec.LookPath("firecracker"); err == nil {
		return true
	}
	if _, err := exec.LookPath("krunvm"); err == nil {
		return true
	}
	return false
}

func (d *LinuxKVMDriver) VerifyPrerequisites(ctx context.Context) error {
	if runtime.GOOS != "linux" {
		return &ErrHypervisorNotSupported{Reason: "host OS is not linux"}
	}

	// Verify /dev/kvm read/write accessibility
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return &ErrHypervisorNotSupported{Reason: "/dev/kvm is not accessible or KVM is disabled"}
	}
	_ = f.Close()

	if !hasLinuxMicroVMAppliance() {
		return &ErrHypervisorNotSupported{Reason: "Firecracker / libkrun microVM appliance image not provisioned (pass --allow-degraded-local to explicitly permit degraded host-OS sandbox)"}
	}

	return nil
}

func (d *LinuxKVMDriver) SpawnVM(ctx context.Context, cfg VMConfig) (VMHandle, error) {
	if err := d.VerifyPrerequisites(ctx); err != nil {
		if cfg.AllowDegradedLocal {
			return NewLocalProcessDriver().SpawnVM(ctx, cfg)
		}
		return nil, fmt.Errorf("prerequisites check failed: %w", err)
	}

	runner := NewGuestRunner("")
	handle, err := runner.SpawnGuest(ctx, cfg)
	if err != nil {
		if cfg.AllowDegradedLocal {
			return NewLocalProcessDriver().SpawnVM(ctx, cfg)
		}
		return nil, fmt.Errorf("failed to spawn hardware microVM guest: %w", err)
	}

	return handle, nil
}

func (d *LinuxKVMDriver) Teardown(ctx context.Context, handle VMHandle) error {
	return handle.Kill(ctx)
}
