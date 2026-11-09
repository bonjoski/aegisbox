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
	ErrPathEscapesWorkspace = errors.New("security violation: path escapes workspace boundary")
	ErrIllegalSymlinkTarget = errors.New("security violation: symlink points outside workspace boundary")
	ErrQuotaExceeded        = errors.New("workspace modification quota exceeded")
	ErrDiffAuditBlocked     = errors.New("semantic diff audit blocked host apply")
)

func isWithinRoot(candidate, rootDir string) bool {
	cleanRoot := filepath.Clean(rootDir)
	cleanCandidate := filepath.Clean(candidate)
	return cleanCandidate == cleanRoot || strings.HasPrefix(cleanCandidate, cleanRoot+string(filepath.Separator))
}

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
		canonical = filepath.Clean(abs)
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
	if strings.ContainsRune(relPath, '\x00') {
		return "", fmt.Errorf("%w: NUL byte in path", ErrPathEscapesWorkspace)
	}
	cleanRel := filepath.Clean(relPath)
	if cleanRel == "." ||
		cleanRel == ".." ||
		strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(cleanRel) ||
		strings.HasPrefix(cleanRel, "/") ||
		strings.HasPrefix(cleanRel, "\\") ||
		filepath.VolumeName(cleanRel) != "" {
		return "", fmt.Errorf("%w: %s", ErrPathEscapesWorkspace, relPath)
	}

	fullPath := filepath.Join(g.rootDir, cleanRel)
	if !isWithinRoot(fullPath, g.rootDir) {
		return "", fmt.Errorf("%w: %s", ErrPathEscapesWorkspace, relPath)
	}

	return fullPath, nil
}

// InspectFile checks a file path (including all intermediate parent directories)
// for directory traversal and symlink escapes.
func (g *SafePathGuard) InspectFile(relPath string) (isSymlink bool, err error) {
	fullPath, err := g.ValidateRelativePath(relPath)
	if err != nil {
		return false, err
	}

	cleanRel := filepath.Clean(relPath)
	segments := strings.Split(cleanRel, string(filepath.Separator))

	// Walk every intermediate directory segment first so parent-directory symlinks cannot escape
	cur := g.rootDir
	for i := 0; i < len(segments)-1; i++ {
		cur = filepath.Join(cur, segments[i])
		segFi, lErr := os.Lstat(cur)
		if lErr != nil {
			if os.IsNotExist(lErr) {
				return false, nil
			}
			return false, fmt.Errorf("failed to lstat intermediate segment %q: %w", cur, lErr)
		}
		if segFi.Mode()&os.ModeSymlink != 0 {
			if checkErr := g.verifySymlinkTarget(cur, relPath); checkErr != nil {
				return true, checkErr
			}
			return true, fmt.Errorf("%w: intermediate directory symlink %s not permitted", ErrIllegalSymlinkTarget, segments[i])
		}
	}

	fi, err := os.Lstat(fullPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to lstat %q: %w", fullPath, err)
	}

	if fi.Mode()&os.ModeSymlink != 0 {
		if checkErr := g.verifySymlinkTarget(fullPath, relPath); checkErr != nil {
			return true, checkErr
		}
		return true, nil
	}

	return false, nil
}

func (g *SafePathGuard) verifySymlinkTarget(fullPath, relPath string) error {
	target, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		linkTarget, rErr := os.Readlink(fullPath)
		if rErr != nil {
			return fmt.Errorf("failed to read symlink %q: %w", fullPath, rErr)
		}
		if filepath.IsAbs(linkTarget) && !isWithinRoot(linkTarget, g.rootDir) {
			return fmt.Errorf("%w: absolute symlink %s -> %s", ErrIllegalSymlinkTarget, relPath, linkTarget)
		}
		resolvedAbs := filepath.Clean(filepath.Join(filepath.Dir(fullPath), linkTarget))
		if !isWithinRoot(resolvedAbs, g.rootDir) {
			return fmt.Errorf("%w: relative symlink %s -> %s escapes workspace", ErrIllegalSymlinkTarget, relPath, linkTarget)
		}
		return nil
	}

	if !isWithinRoot(target, g.rootDir) {
		return fmt.Errorf("%w: symlink %s -> %s", ErrIllegalSymlinkTarget, relPath, target)
	}
	return nil
}

// SafeCopyBetweenRoots copies relPath from srcRootDir to dstRootDir using kernel-confined
// Go 1.24+ os.OpenRoot handles so neither intermediate directory symlinks nor leaf symlinks
// can ever escape srcRootDir or dstRootDir (TOCTOU-resistant O_NOFOLLOW traversal).
func SafeCopyBetweenRoots(srcRootDir, dstRootDir, relPath string, maxBytes int64) error {
	srcGuard, err := NewSafePathGuard(srcRootDir)
	if err != nil {
		return err
	}
	dstGuard, err := NewSafePathGuard(dstRootDir)
	if err != nil {
		return err
	}
	if _, err := srcGuard.ValidateRelativePath(relPath); err != nil {
		return err
	}
	if _, err := dstGuard.ValidateRelativePath(relPath); err != nil {
		return err
	}

	cleanRel := filepath.Clean(relPath)

	srcRoot, err := os.OpenRoot(srcGuard.RootDir())
	if err != nil {
		return fmt.Errorf("failed to open source root %q: %w", srcGuard.RootDir(), err)
	}
	defer srcRoot.Close()

	dstRoot, err := os.OpenRoot(dstGuard.RootDir())
	if err != nil {
		return fmt.Errorf("failed to open destination root %q: %w", dstGuard.RootDir(), err)
	}
	defer dstRoot.Close()

	// Reject any intermediate symlink in source or destination root
	segments := strings.Split(cleanRel, string(filepath.Separator))
	var partial string
	for i := 0; i < len(segments)-1; i++ {
		if i == 0 {
			partial = segments[i]
		} else {
			partial = partial + string(filepath.Separator) + segments[i]
		}

		sFi, sErr := srcRoot.Lstat(partial)
		if sErr != nil {
			return fmt.Errorf("source intermediate directory %q invalid: %w", partial, sErr)
		}
		if sFi.Mode()&os.ModeSymlink != 0 || !sFi.IsDir() {
			return fmt.Errorf("%w: source intermediate component %q is a symlink or non-directory", ErrIllegalSymlinkTarget, partial)
		}

		dFi, dErr := dstRoot.Lstat(partial)
		if dErr != nil {
			if os.IsNotExist(dErr) {
				if mkErr := dstRoot.Mkdir(partial, 0755); mkErr != nil {
					return fmt.Errorf("failed creating host directory %q: %w", partial, mkErr)
				}
			} else {
				return fmt.Errorf("destination intermediate directory %q invalid: %w", partial, dErr)
			}
		} else if dFi.Mode()&os.ModeSymlink != 0 || !dFi.IsDir() {
			return fmt.Errorf("%w: destination intermediate component %q is a symlink or non-directory", ErrIllegalSymlinkTarget, partial)
		}
	}

	srcFi, err := srcRoot.Lstat(cleanRel)
	if err != nil {
		return fmt.Errorf("failed to lstat source %q: %w", cleanRel, err)
	}
	if srcFi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: refusing to copy symlink %q onto host filesystem", ErrIllegalSymlinkTarget, cleanRel)
	}
	if !srcFi.Mode().IsRegular() {
		return fmt.Errorf("refusing to copy non-regular file %q onto host filesystem", cleanRel)
	}
	if srcFi.Size() > maxBytes {
		return fmt.Errorf("%w: file %q size %d exceeds max %d", ErrQuotaExceeded, cleanRel, srcFi.Size(), maxBytes)
	}

	if dstFi, err := dstRoot.Lstat(cleanRel); err == nil {
		if dstFi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: refusing to write through host symlink %q", ErrIllegalSymlinkTarget, cleanRel)
		}
		if os.SameFile(srcFi, dstFi) {
			return fmt.Errorf("security violation: source and destination share the same filesystem inode (hardlink trap detected on %q)", cleanRel)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to lstat destination %q: %w", cleanRel, err)
	}

	in, err := srcRoot.Open(cleanRel)
	if err != nil {
		return fmt.Errorf("failed to open source file %q: %w", cleanRel, err)
	}
	defer in.Close()

	// Verify opened fd matches Lstat regular file
	inFi, err := in.Stat()
	if err != nil || !os.SameFile(srcFi, inFi) {
		return fmt.Errorf("security violation: source file %q changed during copy", cleanRel)
	}

	out, err := dstRoot.OpenFile(cleanRel, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, srcFi.Mode().Perm())
	if err != nil {
		return fmt.Errorf("failed to open destination file %q: %w", cleanRel, err)
	}
	defer out.Close()

	written, err := io.Copy(out, io.LimitReader(in, maxBytes+1))
	if err != nil {
		return fmt.Errorf("failed copying %q: %w", cleanRel, err)
	}
	if written > maxBytes {
		return fmt.Errorf("%w: copied bytes exceeded limit of %d", ErrQuotaExceeded, maxBytes)
	}

	return nil
}

// SafeCopyFile copies a regular file from src to dst using os.OpenRoot containment
// on their parent directories, refusing to follow symlinks or exceed maxBytes.
func SafeCopyFile(src, dst string, maxBytes int64) error {
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return fmt.Errorf("invalid source path %q: %w", src, err)
	}
	absDst, err := filepath.Abs(dst)
	if err != nil {
		return fmt.Errorf("invalid destination path %q: %w", dst, err)
	}

	srcFi, err := os.Lstat(absSrc)
	if err != nil {
		return err
	}
	if srcFi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: refusing to copy symlink %q onto host filesystem", ErrIllegalSymlinkTarget, src)
	}
	if !srcFi.Mode().IsRegular() {
		return fmt.Errorf("refusing to copy non-regular file %q", src)
	}
	if srcFi.Size() > maxBytes {
		return fmt.Errorf("%w: file %q size %d exceeds max %d", ErrQuotaExceeded, src, srcFi.Size(), maxBytes)
	}

	dstDir := filepath.Dir(absDst)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return err
	}

	srcRoot, err := os.OpenRoot(filepath.Dir(absSrc))
	if err != nil {
		return fmt.Errorf("failed to open source parent root: %w", err)
	}
	defer srcRoot.Close()

	dstRoot, err := os.OpenRoot(dstDir)
	if err != nil {
		return fmt.Errorf("failed to open destination parent root: %w", err)
	}
	defer dstRoot.Close()

	srcBase := filepath.Base(absSrc)
	dstBase := filepath.Base(absDst)

	if dstFi, err := dstRoot.Lstat(dstBase); err == nil {
		if dstFi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: refusing to write through host symlink %q", ErrIllegalSymlinkTarget, dst)
		}
		if os.SameFile(srcFi, dstFi) {
			return fmt.Errorf("security violation: source and destination share the same filesystem inode (hardlink trap detected on %q)", dst)
		}
	}

	in, err := srcRoot.Open(srcBase)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := dstRoot.OpenFile(dstBase, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, srcFi.Mode().Perm())
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
