package workspace

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScavengeOrphanedSessions(t *testing.T) {
	tempSessionsDir := t.TempDir()

	// 1. Create a fresh session directory (1 minute old)
	freshDir := filepath.Join(tempSessionsDir, "session-fresh")
	if err := os.MkdirAll(freshDir, 0700); err != nil {
		t.Fatalf("failed to create fresh dir: %v", err)
	}

	// 2. Create an abandoned session directory (48 hours old)
	staleDir := filepath.Join(tempSessionsDir, "session-stale")
	if err := os.MkdirAll(staleDir, 0700); err != nil {
		t.Fatalf("failed to create stale dir: %v", err)
	}
	oldTime := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(staleDir, oldTime, oldTime); err != nil {
		t.Fatalf("failed to set modification time on stale dir: %v", err)
	}

	// 3. Run scavenger with 24 hour threshold
	purged, err := ScavengeOrphanedSessions(tempSessionsDir, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScavengeOrphanedSessions failed: %v", err)
	}

	if purged != 1 {
		t.Errorf("expected 1 session purged, got %d", purged)
	}

	// 4. Verify fresh dir exists and stale dir is removed
	if _, err := os.Stat(freshDir); os.IsNotExist(err) {
		t.Errorf("fresh directory was improperly removed")
	}
	if _, err := os.Stat(staleDir); !os.IsNotExist(err) {
		t.Errorf("stale directory was not removed")
	}
}

func TestWorkspaceManager_Scavenge(t *testing.T) {
	tempSessionsDir := t.TempDir()
	mgr, err := NewWorkspaceManager(tempSessionsDir)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	staleDir := filepath.Join(tempSessionsDir, "session-mgr-stale")
	if err := os.MkdirAll(staleDir, 0700); err != nil {
		t.Fatalf("failed to create stale dir: %v", err)
	}
	oldTime := time.Now().Add(-30 * time.Hour)
	_ = os.Chtimes(staleDir, oldTime, oldTime)

	purged, err := mgr.Scavenge(24 * time.Hour)
	if err != nil {
		t.Fatalf("mgr.Scavenge failed: %v", err)
	}
	if purged != 1 {
		t.Errorf("expected 1 purged, got %d", purged)
	}
}
