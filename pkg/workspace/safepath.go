package workspace

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrPathEscapesWorkspace = errors.New("path escapes workspace boundary")
	ErrIllegalSymlinkTarget = errors.New("symlink points outside workspace boundary")
	ErrQuotaExceeded        = errors.New("workspace modification quota exceeded")
)

// SafePathGuard validates and enforces filesystem containment within a base root.
type SafePathGuard struct {
	rootDir string
}

// NewSafePathGuard creates a new SafePathGuard for the given root directory.
func NewSafePathGuard(rootDir string) (*SafePathGuard, error) {
	abs, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for root %q: %w", rootDir, err)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		canonical = abs
	}
	return &SafePathGuard{rootDir: canonical}, nil
}

// RootDir returns the canonical root directory.
func (g *SafePathGuard) RootDir() string {
	return g.rootDir
}

// ValidateRelativePath ensures relPath does not perform directory traversal (..)
// and that its combined path is strictly inside RootDir.
func (g *SafePathGuard) ValidateRelativePath(relPath string) (string, error) {
	cleanRel := filepath.Clean(relPath)
	if strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
		return "", fmt.Errorf("%w: %s", ErrPathEscapesWorkspace, relPath)
	}

	fullPath := filepath.Join(g.rootDir, cleanRel)
	if !strings.HasPrefix(fullPath, g.rootDir+string(filepath.Separator)) && fullPath != g.rootDir {
		return "", fmt.Errorf("%w: %s", ErrPathEscapesWorkspace, relPath)
	}

	return fullPath, nil
}

// InspectFile checks a file path for directory traversal and symlink escapes.
// If the path is a symlink, it verifies that the target resolves strictly inside RootDir.
func (g *SafePathGuard) InspectFile(relPath string) (isSymlink bool, err error) {
	fullPath, err := g.ValidateRelativePath(relPath)
	if err != nil {
		return false, err
	}

	fi, err := os.Lstat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to lstat %q: %w", fullPath, err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		isSymlink = true
		target, err := filepath.EvalSymlinks(fullPath)
		if err != nil {
			// If target doesn't exist, readlink to check relative target
			linkTarget, rErr := os.Readlink(fullPath)
			if rErr != nil {
				return true, fmt.Errorf("failed to read symlink %q: %w", fullPath, rErr)
			}
			if filepath.IsAbs(linkTarget) && !strings.HasPrefix(linkTarget, g.rootDir) {
				return true, fmt.Errorf("%w: absolute symlink %s -> %s", ErrIllegalSymlinkTarget, relPath, linkTarget)
			}
			resolvedAbs := filepath.Clean(filepath.Join(filepath.Dir(fullPath), linkTarget))
			if !strings.HasPrefix(resolvedAbs, g.rootDir) {
				return true, fmt.Errorf("%w: relative symlink %s -> %s escapes workspace", ErrIllegalSymlinkTarget, relPath, linkTarget)
			}
			return true, nil
		}

		if !strings.HasPrefix(target, g.rootDir+string(filepath.Separator)) && target != g.rootDir {
			return true, fmt.Errorf("%w: symlink %s -> %s", ErrIllegalSymlinkTarget, relPath, target)
		}
	}

	return isSymlink, nil
}

// SafeCopyFile copies a regular file from src (in shadow) to dst (in host),
// refusing to follow escaping symlinks or traverse outside boundaries.
func SafeCopyFile(src, dst string, maxBytes int64) error {
	srcFi, err := os.Lstat(src)
	if err != nil {
		return err
	}

	// Refuse copying symlinks directly onto host unless it's a regular file
	if srcFi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to copy symlink %q onto host filesystem", src)
	}

	if srcFi.Size() > maxBytes {
		return fmt.Errorf("%w: file %q size %d exceeds max %d", ErrQuotaExceeded, src, srcFi.Size(), maxBytes)
	}

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	// Write with O_CREATE|O_TRUNC|O_WRONLY
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, srcFi.Mode().Perm())
	if err != nil {
		return err
	}
	defer out.Close()

	written, err := io.Copy(out, io.LimitReader(in, maxBytes+1))
	if err != nil {
		return err
	}
	if written > maxBytes {
		return fmt.Errorf("%w: copied bytes exceeded limit of %d", ErrQuotaExceeded, maxBytes)
	}

	return nil
}
