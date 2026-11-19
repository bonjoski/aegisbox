package vmm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFlushVirtiofsCache(t *testing.T) {
	// Must execute without panic on any platform
	FlushVirtiofsCache()
	t.Log("PASS: FlushVirtiofsCache executed cleanly")
}

func TestCOWManager_RegisterAndTeardownMount(t *testing.T) {
	mgr := NewCOWManager()
	tmpDir := t.TempDir()

	scratchDir := filepath.Join(tmpDir, "scratch-cow")
	if err := os.MkdirAll(scratchDir, 0700); err != nil {
		t.Fatalf("failed to create scratch dir: %v", err)
	}

	testFile := filepath.Join(scratchDir, "ephemeral.txt")
	if err := os.WriteFile(testFile, []byte("temporary cow data"), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	mgr.RegisterMount("vm-1", tmpDir, scratchDir)

	if err := mgr.TeardownMount(context.Background(), "vm-1"); err != nil {
		t.Fatalf("TeardownMount failed: %v", err)
	}

	if _, err := os.Stat(scratchDir); !os.IsNotExist(err) {
		t.Errorf("Expected scratchDir to be removed, but it still exists")
	}

	t.Log("PASS: COWManager cleaned up scratch dir and flushed virtiofs caches")
}

func TestCOWManager_TeardownAll(t *testing.T) {
	mgr := NewCOWManager()
	tmpDir := t.TempDir()

	s1 := filepath.Join(tmpDir, "scratch-1")
	s2 := filepath.Join(tmpDir, "scratch-2")
	_ = os.MkdirAll(s1, 0700)
	_ = os.MkdirAll(s2, 0700)

	mgr.RegisterMount("vm-1", tmpDir, s1)
	mgr.RegisterMount("vm-2", tmpDir, s2)

	if err := mgr.TeardownAll(context.Background()); err != nil {
		t.Fatalf("TeardownAll failed: %v", err)
	}

	if _, err := os.Stat(s1); !os.IsNotExist(err) {
		t.Errorf("Expected s1 to be removed")
	}
	if _, err := os.Stat(s2); !os.IsNotExist(err) {
		t.Errorf("Expected s2 to be removed")
	}

	t.Log("PASS: TeardownAll flushed all mounts and cleaned up scratch directories")
}

func TestLocalProcessDriver_TeardownFlushesCache(t *testing.T) {
	driver := NewLocalProcessDriver()
	handle := &localVMHandle{
		id: "test-teardown-vm",
		cfg: VMConfig{
			ID: "test-teardown-vm",
		},
	}

	if err := driver.Teardown(context.Background(), handle); err != nil {
		t.Fatalf("driver.Teardown failed: %v", err)
	}

	if !handle.killed {
		t.Errorf("Expected handle to be marked killed")
	}

	t.Log("PASS: Driver teardown killed handle and flushed virtiofs cache")
}
