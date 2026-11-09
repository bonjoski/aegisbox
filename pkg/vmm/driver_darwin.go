//go:build darwin

package vmm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// DarwinVZDriver manages microVMs on macOS using Apple's Virtualization.framework / libkrun.
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

func hasMicroVMAppliance() bool {
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

	if _, err := exec.LookPath("krunvm"); err == nil {
		return true
	}
	if _, err := exec.LookPath("aegisbox-vz-helper"); err == nil {
		return true
	}
	return false
}

func (d *DarwinVZDriver) VerifyPrerequisites(ctx context.Context) error {
	if runtime.GOOS != "darwin" {
		return &ErrHypervisorNotSupported{Reason: "host OS is not darwin/macOS"}
	}

	// Verify macOS hypervisor capability via sysctl
	out, err := exec.CommandContext(ctx, "sysctl", "-n", "kern.hv_support").Output()
	if err != nil || strings.TrimSpace(string(out)) == "0" {
		return &ErrHypervisorNotSupported{Reason: "Apple Hypervisor entitlement (kern.hv_support) is disabled or not supported"}
	}

	// Fail closed unless the hardware microVM appliance (libkrun / Virtualization.framework rootfs) is provisioned.
	if !hasMicroVMAppliance() {
		return &ErrHypervisorNotSupported{Reason: "libkrun / Apple Virtualization.framework microVM appliance image not provisioned (pass --allow-degraded-local to explicitly permit degraded host-OS sandbox)"}
	}

	return nil
}

func (d *DarwinVZDriver) SpawnVM(ctx context.Context, cfg VMConfig) (VMHandle, error) {
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

func (d *DarwinVZDriver) Teardown(ctx context.Context, handle VMHandle) error {
	return handle.Kill(ctx)
}
