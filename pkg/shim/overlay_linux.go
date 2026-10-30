//go:build linux

package shim

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// platformOverlayShim implements OverlayShim on Linux using kernel user-namespaces and OverlayFS,
// with an unprivileged userspace shadow fallback when running without CAP_SYS_ADMIN.
type platformOverlayShim struct {
	cfg                 OverlayConfig
	scratchDir          string
	upperDir            string
	workDir             string
	mountPoint          string
	mounted             bool
	isUserSpaceFallback bool
	mu                  sync.RWMutex
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

	// 1. Mount tmpfs on scratch directory to back upper and work directories in RAM
	tmpfsOpts := fmt.Sprintf("size=%s,mode=0755", s.cfg.TmpfsSize)
	if err := unix.Mount("tmpfs", s.scratchDir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, tmpfsOpts); err != nil {
		// Non-fatal if tmpfs mount fails (e.g., standard disk fallback)
		_ = os.MkdirAll(s.scratchDir, 0755)
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

	// 2. Mount OverlayFS
	// lowerdir=<host_cache>,upperdir=<tmpfs>/upper,workdir=<tmpfs>/work
	overlayOpts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", s.cfg.LowerDir, s.upperDir, s.workDir)
	if err := unix.Mount("overlay", s.mountPoint, "overlay", 0, overlayOpts); err != nil {
		// In unprivileged environments (e.g. CI containers without CAP_SYS_ADMIN), fall back to shadow copying
		if err == unix.EPERM || err == unix.EACCES || err == unix.ENOSYS || err == unix.EINVAL {
			if shadowErr := s.shadowLowerDir(s.cfg.LowerDir, s.mountPoint); shadowErr != nil {
				return fmt.Errorf("overlayfs mount failed (%v) and shadow fallback failed: %w", err, shadowErr)
			}
			s.mounted = true
			s.isUserSpaceFallback = true
			return nil
		}
		return fmt.Errorf("failed to mount overlayfs (opts=%s): %w", overlayOpts, err)
	}

	// 3. Prevent host mount leak by marking mount private
	_ = unix.Mount("", s.mountPoint, "", unix.MS_PRIVATE|unix.MS_REC, "")

	// 4. Drop capabilities and enable NO_NEW_PRIVS if requested
	if s.cfg.DropCapabilities {
		_ = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
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

	start := time.Now()

	if !s.isUserSpaceFallback {
		// 1. Instantly unmount overlay using MNT_DETACH (lazy unmount)
		_ = unix.Unmount(s.mountPoint, unix.MNT_DETACH)

		// 2. Unmount tmpfs RAM disk
		_ = unix.Unmount(s.scratchDir, unix.MNT_DETACH)
	}

	// 3. Remove ephemeral scratch directory
	_ = os.RemoveAll(s.scratchDir)

	s.mounted = false
	duration := time.Since(start)
	if duration > 50*time.Millisecond {
		// Log if rollback took longer than expected
		_ = duration
	}

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

	sourceDir := s.upperDir
	if s.isUserSpaceFallback {
		sourceDir = s.mountPoint
	}

	// Walk upperdir (or merged mountpoint in fallback) and copy changes to target
	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == sourceDir {
			return nil
		}

		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(target, rel)

		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode())
		}

		// Copy file contents
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
