package microvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestMicroVMCowManager(t *testing.T) {
	FlushVirtiofsCache()

	tmpDir := t.TempDir()
	scratchDir := filepath.Join(tmpDir, "microvm-scratch")
	_ = os.MkdirAll(scratchDir, 0700)

	mgr := NewCOWManager()
	mgr.RegisterMount("vm-test", tmpDir, scratchDir)

	if err := mgr.TeardownMount(context.Background(), "vm-test"); err != nil {
		t.Fatalf("TeardownMount failed: %v", err)
	}

	if _, err := os.Stat(scratchDir); !os.IsNotExist(err) {
		t.Errorf("scratch directory was not purged")
	}

	if err := PurgeWorktreeCache(context.Background(), "non-existent"); err != nil {
		t.Fatalf("PurgeWorktreeCache failed: %v", err)
	}

	t.Log("PASS: microvm COWManager and cache purge tests passed")
}
