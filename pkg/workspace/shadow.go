package workspace

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ShadowMode defines the workspace isolation strategy.
type ShadowMode string

const (
	ModeGitWorktree ShadowMode = "worktree"
	ModeOverlayCoW  ShadowMode = "cow"
	ModeDirect      ShadowMode = "direct" // Dry-run or test
)

// ShadowConfig defines configuration for an isolated workspace session.
type ShadowConfig struct {
	BaseDir      string        `json:"base_dir"`
	Mode         ShadowMode    `json:"mode"`
	MaskPatterns []string      `json:"mask_patterns"`
	SyntheticEnv map[string]string `json:"synthetic_env,omitempty"`
	ReadOnlyGit  bool          `json:"read_only_git"`
}

// SessionWorkspace represents an active isolated workspace.
type SessionWorkspace interface {
	ID() string
	ShadowDir() string
	CaptureDiff(ctx context.Context) (*DiffReport, error)
	ApplyToHost(ctx context.Context) error
	Cleanup(ctx context.Context) error
}

// DiffReport summarizes all changes made inside the shadow session.
type DiffReport struct {
	SessionID   string    `json:"session_id"`
	GeneratedAt time.Time `json:"generated_at"`
	FilesAdded  []string  `json:"files_added"`
	FilesModified []string `json:"files_modified"`
	FilesDeleted []string `json:"files_deleted"`
	RawDiff     string    `json:"raw_diff,omitempty"`
}

// WorkspaceManager creates and tracks ephemeral shadow workspaces.
type WorkspaceManager struct {
	sessionsDir string
}

// NewWorkspaceManager returns a new WorkspaceManager.
func NewWorkspaceManager(sessionsDir string) (*WorkspaceManager, error) {
	if sessionsDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get user home directory: %w", err)
		}
		sessionsDir = filepath.Join(home, ".aegisbox", "sessions")
	}


	if err := os.MkdirAll(sessionsDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create sessions directory %q: %w", sessionsDir, err)
	}

	return &WorkspaceManager{sessionsDir: sessionsDir}, nil
}
