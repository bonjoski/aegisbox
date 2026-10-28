package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ScavengeOrphanedSessions scans the sessions directory and deletes directories
// that have not been modified within maxAge. It returns the count of purged sessions.
func ScavengeOrphanedSessions(sessionsDir string, maxAge time.Duration) (int, error) {
	if sessionsDir == "" {
		return 0, nil
	}

	fi, err := os.Stat(sessionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to stat sessions directory %q: %w", sessionsDir, err)
	}
	if !fi.IsDir() {
		return 0, fmt.Errorf("sessions path %q is not a directory", sessionsDir)
	}

	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read sessions directory %q: %w", sessionsDir, err)
	}

	now := time.Now()
	purged := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if now.Sub(info.ModTime()) > maxAge {
			dirPath := filepath.Join(sessionsDir, entry.Name())
			if err := os.RemoveAll(dirPath); err == nil {
				purged++
			}
		}
	}

	return purged, nil
}

// Scavenge scans and cleans up abandoned sessions in the manager's sessions directory.
func (m *WorkspaceManager) Scavenge(maxAge time.Duration) (int, error) {
	if m == nil || m.sessionsDir == "" {
		return 0, nil
	}
	return ScavengeOrphanedSessions(m.sessionsDir, maxAge)
}
