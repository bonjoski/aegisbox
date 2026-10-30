package vmm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGuestRunner_FailClosedWhenNoHypervisor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	runner := NewGuestRunner("dummy-bin")
	_, err := runner.SpawnGuest(ctx, VMConfig{
		ID: "fail-closed-test",
	})
	if err == nil {
		t.Fatalf("expected error failing closed when no hypervisor is available")
	}
	if !strings.Contains(err.Error(), "hardware hypervisor microVM guest is not available") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestGuestRunner_LifecycleAndExecution(t *testing.T) {
	t.Setenv("AEGISBOX_TEST_GUEST", "1")
	// Look for compiled binary in project root / bin
	binPath := filepath.Join("..", "..", "bin", "aegisbox-guest")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		t.Skip("aegisbox-guest binary not found in bin/, skipping live daemon test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	runner := NewGuestRunner(binPath)
	handle, err := runner.SpawnGuest(ctx, VMConfig{
		ID:       "test-vm-001",
		VCPU:     1,
		MemoryMB: 256,
	})
	if err != nil {
		t.Fatalf("failed to spawn guest daemon: %v", err)
	}
	defer handle.Kill(ctx)

	// Test basic command execution
	res, err := handle.ExecuteInGuest(ctx, "echo 'hello from microvm'", nil)
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}
	if res.Stdout != "hello from microvm\n" {
		t.Errorf("unexpected stdout: %q", res.Stdout)
	}

	// Test environment isolation
	resEnv, err := handle.ExecuteInGuest(ctx, "echo $CUSTOM_VAR", map[string]string{
		"CUSTOM_VAR": "aegisbox-secure-env",
	})
	if err != nil {
		t.Fatalf("env execution failed: %v", err)
	}
	if resEnv.Stdout != "aegisbox-secure-env\n" {
		t.Errorf("unexpected env output: %q", resEnv.Stdout)
	}

	// Test kill
	if err := handle.Kill(ctx); err != nil {
		t.Errorf("failed to kill guest handle: %v", err)
	}
}

func TestGuestRunner_SignalBridgeIntegration(t *testing.T) {
	t.Setenv("AEGISBOX_TEST_GUEST", "1")
	binPath := filepath.Join("..", "..", "bin", "aegisbox-guest")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		t.Skip("aegisbox-guest binary not found in bin/, skipping live daemon test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	runner := NewGuestRunner(binPath)
	handle, err := runner.SpawnGuest(ctx, VMConfig{
		ID: "test-vm-sigbridge",
	})
	if err != nil {
		t.Fatalf("failed to spawn guest daemon: %v", err)
	}
	defer handle.Kill(ctx)

	bridgeHandle, err := handle.EnableSignalBridge(ctx)
	if err != nil {
		t.Fatalf("failed to enable signal bridge: %v", err)
	}
	if bridgeHandle == nil {
		t.Fatal("expected non-nil signal bridge handle")
	}

	// Verify command execution while signal bridge is active
	res, err := handle.ExecuteInGuest(ctx, "echo 'signal bridge active'", nil)
	if err != nil {
		t.Fatalf("failed execution with signal bridge: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "signal bridge active") {
		t.Errorf("unexpected execution result: %+v", res)
	}
}
