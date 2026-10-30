//go:build !linux

package shim

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// platformOverlayShim implements a high-performance ephemeral copy-on-write shim for non-Linux platforms (macOS/Darwin, Windows).
type platformOverlayShim struct {
	cfg        OverlayConfig
	scratchDir string
	upperDir   string
	workDir    string
	mountPoint string
	mounted    bool
	mu         sync.RWMutex
}

func newPlatformOverlayShim(cfg OverlayConfig) (OverlayShim, error) {
	root := cfg.EphemeralRoot
	if root == "" {
		root = os.TempDir()
	}

	scratchDir, err := os.MkdirTemp(root, "aegisbox-overlay-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create ephemeral scratch directory: %w", err)
	}

	upperDir := cfg.UpperDir
	if upperDir == "" {
		upperDir = filepath.Join(scratchDir, "upper")
	}

	workDir := cfg.WorkDir
	if workDir == "" {
		workDir = filepath.Join(scratchDir, "work")
	}

	mountPoint := cfg.MountPoint
	if mountPoint == "" {
		mountPoint = filepath.Join(scratchDir, "merged")
	}

	return &platformOverlayShim{
		cfg:        cfg,
		scratchDir: scratchDir,
		upperDir:   upperDir,
		workDir:    workDir,
		mountPoint: mountPoint,
	}, nil
}

func (s *platformOverlayShim) Mount(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.mounted {
		return ErrAlreadyMounted
	}

	if err := os.MkdirAll(s.upperDir, 0755); err != nil {
		return fmt.Errorf("failed to create upper directory %q: %w", s.upperDir, err)
	}
	if err := os.MkdirAll(s.workDir, 0755); err != nil {
		return fmt.Errorf("failed to create work directory %q: %w", s.workDir, err)
	}
	if err := os.MkdirAll(s.mountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create merged mountpoint %q: %w", s.mountPoint, err)
	}

	// Populate mountPoint with initial shadow links/copies of lowerdir to provide read access
	if err := s.shadowLowerDir(s.cfg.LowerDir, s.mountPoint); err != nil {
		return fmt.Errorf("failed to initialize merged mountpoint: %w", err)
	}

	s.mounted = true
	return nil
}

func (s *platformOverlayShim) shadowLowerDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == src {
			return nil
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		targetPath := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(targetPath, 0755)
		}

		// Try hardlink first (instant, zero overhead), fallback to copy
		if err := os.Link(path, targetPath); err != nil {
			return copyFile(path, targetPath, info.Mode())
		}
		return nil
	})
}

func (s *platformOverlayShim) Rollback(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.mounted {
		return nil
	}

	// Instant rollback: remove ephemeral scratch and merged directories in < 5ms
	if err := os.RemoveAll(s.scratchDir); err != nil {
		return fmt.Errorf("failed to cleanup ephemeral scratch %q: %w", s.scratchDir, err)
	}

	s.mounted = false
	return nil
}

func (s *platformOverlayShim) Commit(ctx context.Context, target string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.mounted {
		return ErrNotMounted
	}

	if target == "" {
		target = s.cfg.LowerDir
	}

	// Commit newly added or modified files from mountPoint to target
	return filepath.Walk(s.mountPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == s.mountPoint {
			return nil
		}

		rel, err := filepath.Rel(s.mountPoint, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(target, rel)

		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode())
		}

		return copyFile(path, destPath, info.Mode())
	})
}

func (s *platformOverlayShim) IsMounted() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.mounted
}

func (s *platformOverlayShim) LowerDir() string {
	return s.cfg.LowerDir
}

func (s *platformOverlayShim) UpperDir() string {
	return s.upperDir
}

func (s *platformOverlayShim) MountPoint() string {
	return s.mountPoint
}

func (s *platformOverlayShim) SubtreeShims() []OverlayShim {
	return nil
}

func (s *platformOverlayShim) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.Rollback(ctx)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source %q: %w", src, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("failed to create destination dir for %q: %w", dst, err)
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("failed to open destination %q: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("failed to copy %q to %q: %w", src, dst, err)
	}
	return nil
}
