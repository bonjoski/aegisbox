package vmm

import (
	"context"
	"strings"
	"testing"
)

func TestGenerateSpec_Defaults(t *testing.T) {
	spec, err := GenerateSpec(VMConfig{
		ID:             "spec-test-01",
		WorkspaceMount: "/tmp/workspace",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if spec.VCPUs != 2 {
		t.Errorf("expected default 2 VCPUs, got %d", spec.VCPUs)
	}
	if spec.MemoryBytes != 512*1024*1024 {
		t.Errorf("expected default 512MB, got %d bytes", spec.MemoryBytes)
	}
	if spec.WorkspaceShare != "/tmp/workspace" {
		t.Errorf("expected workspace share '/tmp/workspace', got %q", spec.WorkspaceShare)
	}

	// Test Firecracker export
	fcJSON, err := spec.ExportFirecrackerConfig()
	if err != nil {
		t.Fatalf("failed to export firecracker config: %v", err)
	}
	if !strings.Contains(string(fcJSON), "machine-config") {
		t.Errorf("expected machine-config in Firecracker export")
	}

	// Test Apple VZ export
	vzJSON, err := spec.ExportAppleVZSpec()
	if err != nil {
		t.Fatalf("failed to export apple vz config: %v", err)
	}
	if !strings.Contains(string(vzJSON), "VZLinuxBootLoader") {
		t.Errorf("expected VZLinuxBootLoader in Apple VZ export")
	}
}

func TestDirectHypervisorManager_Prerequisites(t *testing.T) {
	mgr := NewDirectHypervisorManager()
	ctx := context.Background()

	spec, err := mgr.PrepareBoot(ctx, VMConfig{
		ID:       "boot-test-01",
		VCPU:     4,
		MemoryMB: 1024,
	})
	if err != nil {
		if strings.Contains(err.Error(), "hypervisor not supported") {
			t.Skipf("skipping on host without hardware virtualization support: %v", err)
		}
		t.Fatalf("failed to prepare boot: %v", err)
	}

	if spec.VCPUs != 4 {
		t.Errorf("expected 4 VCPUs, got %d", spec.VCPUs)
	}
}
