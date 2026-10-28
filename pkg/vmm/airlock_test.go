package vmm

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDiscoverAirlock_EnvOverride(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake-airlock")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("failed to create fake airlock: %v", err)
	}

	orig := os.Getenv("AIRLOCK_PATH")
	defer os.Setenv("AIRLOCK_PATH", orig)

	os.Setenv("AIRLOCK_PATH", fakeBin)
	p, err := DiscoverAirlock()
	if err != nil {
		t.Fatalf("DiscoverAirlock failed: %v", err)
	}
	if p != fakeBin {
		t.Errorf("expected %q, got %q", fakeBin, p)
	}
}

func TestExecuteAirlock_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell script execution test on Windows (Airlock is Linux/macOS only)")
	}

	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake-airlock-runner")
	script := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake runner: %v", err)
	}

	orig := os.Getenv("AIRLOCK_PATH")
	defer os.Setenv("AIRLOCK_PATH", orig)

	os.Setenv("AIRLOCK_PATH", fakeBin)
	code, err := ExecuteAirlock(context.Background(), AirlockOpts{}, []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("ExecuteAirlock failed: %v", err)
	}
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}
