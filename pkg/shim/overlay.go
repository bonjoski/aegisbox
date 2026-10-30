package shim

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Common errors for OverlayFS operations.
var (
	ErrNotMounted       = errors.New("overlay shim is not mounted")
	ErrAlreadyMounted   = errors.New("overlay shim is already mounted")
	ErrLowerDirRequired = errors.New("lowerdir is required and must exist")
)

// OverlayConfig defines the configuration for the ephemeral user-namespace OverlayFS shim.
type OverlayConfig struct {
	// LowerDir is the read-only host workspace or dependency cache.
	LowerDir string `json:"lower_dir"`

	// UpperDir is the writable upper layer directory. If empty, created inside ephemeral scratch.
	UpperDir string `json:"upper_dir,omitempty"`

	// WorkDir is the scratch working directory required by OverlayFS. If empty, created inside ephemeral scratch.
	WorkDir string `json:"work_dir,omitempty"`

	// MountPoint is the target merged directory exposed to the build process.
	MountPoint string `json:"mount_point,omitempty"`

	// TmpfsSize defines the RAM disk size limit for the upper layer (e.g. "2G", "512M").
	TmpfsSize string `json:"tmpfs_size,omitempty"`

	// EphemeralRoot specifies the parent directory for temporary scratch directories.
	EphemeralRoot string `json:"ephemeral_root,omitempty"`

	// SubtreeTargets lists specific dependency paths (e.g., "node_modules", "target", "build")
	// to isolate via OverlayFS. If empty, the entire workspace is layered.
	SubtreeTargets []string `json:"subtree_targets,omitempty"`

	// DropCapabilities indicates whether to drop bounding set capabilities in user namespace.
	DropCapabilities bool `json:"drop_capabilities,omitempty"`
}

// OverlayShim defines the public contract for ephemeral layered filesystems.
type OverlayShim interface {
	// Mount sets up the user-namespace mount and overlay layers.
	Mount(ctx context.Context) error

	// Rollback unmounts the overlay and tmpfs, discarding all ephemeral writes in < 5ms.
	Rollback(ctx context.Context) error

	// Commit copies modified and newly created files from UpperDir into the target directory.
	Commit(ctx context.Context, target string) error

	// IsMounted returns true if the overlay is currently active.
	IsMounted() bool

	// LowerDir returns the path to the read-only lower directory.
	LowerDir() string

	// UpperDir returns the path to the ephemeral upper directory.
	UpperDir() string

	// MountPoint returns the path to the merged mount directory.
	MountPoint() string

	// SubtreeShims returns any nested sub-tree overlay shims created for SubtreeTargets.
	SubtreeShims() []OverlayShim

	// Close cleans up all mounts and ephemeral files.
	Close() error
}

// SubtreeOverlayManager manages multi-target overlay shims (e.g. node_modules, target).
type SubtreeOverlayManager struct {
	cfg          OverlayConfig
	subShims     []OverlayShim
	mu           sync.RWMutex
	mounted      bool
}

// NewOverlayShim creates an OverlayShim instance suited for the runtime operating system.
func NewOverlayShim(cfg OverlayConfig) (OverlayShim, error) {
	if cfg.LowerDir == "" {
		return nil, ErrLowerDirRequired
	}

	absLower, err := filepath.Abs(cfg.LowerDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve lowerdir path %q: %w", cfg.LowerDir, err)
	}
	cfg.LowerDir = absLower

	if fi, err := os.Stat(cfg.LowerDir); err != nil {
		return nil, fmt.Errorf("lowerdir does not exist (%q): %w", cfg.LowerDir, err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("lowerdir is not a directory (%q)", cfg.LowerDir)
	}

	if cfg.TmpfsSize == "" {
		cfg.TmpfsSize = "2G"
	}

	if len(cfg.SubtreeTargets) > 0 {
		return newSubtreeOverlayManager(cfg)
	}

	return newPlatformOverlayShim(cfg)
}

func newSubtreeOverlayManager(cfg OverlayConfig) (*SubtreeOverlayManager, error) {
	mgr := &SubtreeOverlayManager{
		cfg:      cfg,
		subShims: make([]OverlayShim, 0, len(cfg.SubtreeTargets)),
	}

	for _, target := range cfg.SubtreeTargets {
		targetLower := filepath.Join(cfg.LowerDir, target)
		if err := os.MkdirAll(targetLower, 0755); err != nil {
			return nil, fmt.Errorf("failed to prepare lowerdir subtree %q: %w", targetLower, err)
		}

		targetMount := filepath.Join(cfg.LowerDir, target)
		if cfg.MountPoint != "" {
			targetMount = filepath.Join(cfg.MountPoint, target)
		}

		subCfg := OverlayConfig{
			LowerDir:         targetLower,
			MountPoint:       targetMount,
			TmpfsSize:        cfg.TmpfsSize,
			EphemeralRoot:    cfg.EphemeralRoot,
			DropCapabilities: cfg.DropCapabilities,
		}

		subShim, err := newPlatformOverlayShim(subCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create sub-overlay shim for %q: %w", target, err)
		}
		mgr.subShims = append(mgr.subShims, subShim)
	}

	return mgr, nil
}

func (m *SubtreeOverlayManager) Mount(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.mounted {
		return ErrAlreadyMounted
	}

	for i, shim := range m.subShims {
		if err := shim.Mount(ctx); err != nil {
			// Rollback previously mounted sub-shims on error
			for j := 0; j < i; j++ {
				_ = m.subShims[j].Rollback(ctx)
			}
			return fmt.Errorf("failed to mount sub-shim: %w", err)
		}
	}

	m.mounted = true
	return nil
}

func (m *SubtreeOverlayManager) Rollback(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error
	for _, shim := range m.subShims {
		if err := shim.Rollback(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	m.mounted = false
	if firstErr != nil {
		return fmt.Errorf("error during subtree rollback: %w", firstErr)
	}
	return nil
}

func (m *SubtreeOverlayManager) Commit(ctx context.Context, target string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, shim := range m.subShims {
		if err := shim.Commit(ctx, target); err != nil {
			return fmt.Errorf("failed to commit sub-shim: %w", err)
		}
	}
	return nil
}

func (m *SubtreeOverlayManager) IsMounted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mounted
}

func (m *SubtreeOverlayManager) LowerDir() string {
	return m.cfg.LowerDir
}

func (m *SubtreeOverlayManager) UpperDir() string {
	return ""
}

func (m *SubtreeOverlayManager) MountPoint() string {
	return m.cfg.MountPoint
}

func (m *SubtreeOverlayManager) SubtreeShims() []OverlayShim {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]OverlayShim, len(m.subShims))
	copy(res, m.subShims)
	return res
}

func (m *SubtreeOverlayManager) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return m.Rollback(ctx)
}
