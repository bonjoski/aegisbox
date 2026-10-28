package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCacheManager_ProvisionStaging(t *testing.T) {
	mgr := NewCacheManager()
	tempBase := t.TempDir()

	cfg, err := mgr.ProvisionStaging(tempBase)
	if err != nil {
		t.Fatalf("ProvisionStaging failed: %v", err)
	}

	if cfg.BaseDir != tempBase {
		t.Errorf("expected BaseDir %q, got %q", tempBase, cfg.BaseDir)
	}

	// Verify key runtime environment redirections
	expectedEnvKeys := []string{"npm_config_cache", "PIP_CACHE_DIR", "GOCACHE", "GOMODCACHE"}
	for _, k := range expectedEnvKeys {
		val, exists := cfg.EnvVars[k]
		if !exists || val == "" {
			t.Errorf("expected env var %q to be provisioned", k)
		}
		if _, err := os.Stat(val); os.IsNotExist(err) {
			t.Errorf("staging directory for %q does not exist: %s", k, val)
		}
	}
}

func TestCacheManager_SyncBack_SafeAndSymlinkRejection(t *testing.T) {
	mgr := NewCacheManager()
	fakeHome := t.TempDir()
	stagingBase := t.TempDir()

	cfg, err := mgr.ProvisionStaging(stagingBase)
	if err != nil {
		t.Fatalf("ProvisionStaging failed: %v", err)
	}

	// 1. Create a safe artifact in npm staging
	npmStaging := cfg.EnvVars["npm_config_cache"]
	safeFile := filepath.Join(npmStaging, "pkg-manifest.json")
	if err := os.WriteFile(safeFile, []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// 2. Perform safe sync
	if err := mgr.SyncBack(stagingBase, fakeHome); err != nil {
		t.Fatalf("SyncBack failed: %v", err)
	}

	// Verify file arrived in host cache
	targetFile := filepath.Join(fakeHome, ".npm", "pkg-manifest.json")
	if _, err := os.Stat(targetFile); err != nil {
		t.Fatalf("expected synced file at %s: %v", targetFile, err)
	}

	// 3. Test symlink rejection
	evilSymlink := filepath.Join(npmStaging, "evil-symlink")
	if err := os.Symlink("/etc/passwd", evilSymlink); err == nil {
		err := mgr.SyncBack(stagingBase, fakeHome)
		if err == nil {
			t.Errorf("expected SyncBack to reject symlink, but it succeeded")
		}
		if !errors.Is(err, ErrSymlinkRejected) {
			t.Errorf("expected ErrSymlinkRejected, got %v", err)
		}
	}
}
