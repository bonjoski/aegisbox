package workspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrIllegalDeviceNode = errors.New("security violation: device node (mknod) detected in workspace diff")
	ErrIllegalFIFO       = errors.New("security violation: FIFO/named pipe detected in workspace diff")
	ErrIllegalSocket     = errors.New("security violation: Unix domain socket detected in workspace diff")
	ErrSymlinkEscape     = errors.New("security violation: symlink targets a path outside the workspace boundary")
)

// CommitReport records the files committed or rejected.
type CommitReport struct {
	CommittedFiles []string
	RejectedFiles  []string
	TotalBytes     int64
}

// InodeSanitizer walks an ephemeral upper directory and validates that every file
// is safe before being staged for diff review or host commit.
func InodeSanitizer(workspaceRoot string) error {
	cleanRoot := filepath.Clean(workspaceRoot)

	return filepath.Walk(cleanRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		mode := info.Mode()

		// 1. Block Device Nodes (mknod exploits)
		if mode&os.ModeDevice != 0 {
			return fmt.Errorf("%w: %s (mode %v)", ErrIllegalDeviceNode, path, mode)
		}

		// 2. Block Named Pipes (FIFOs)
		if mode&os.ModeNamedPipe != 0 {
			return fmt.Errorf("%w: %s", ErrIllegalFIFO, path)
		}

		// 3. Block Sockets
		if mode&os.ModeSocket != 0 {
			return fmt.Errorf("%w: %s", ErrIllegalSocket, path)
		}

		// 4. Block Symlink Traversal
		if mode&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("failed to read symlink target %s: %w", path, err)
			}

			var resolved string
			if filepath.IsAbs(target) {
				resolved = filepath.Clean(target)
			} else {
				resolved = filepath.Clean(filepath.Join(filepath.Dir(path), target))
			}

			// Ensure symlink stays within cleanRoot
			if !strings.HasPrefix(resolved, cleanRoot+string(filepath.Separator)) && resolved != cleanRoot {
				return fmt.Errorf("%w: %s -> %s", ErrSymlinkEscape, path, target)
			}
		}

		return nil
	})
}

// CommitSafeDiff copies validated files from the ephemeral upper layer to the host directory.
func CommitSafeDiff(ctx context.Context, upperDir, hostDir string, approvedRelPaths []string) (*CommitReport, error) {
	if err := InodeSanitizer(upperDir); err != nil {
		return nil, fmt.Errorf("pre-commit inode sanitization failed: %w", err)
	}

	report := &CommitReport{
		CommittedFiles: make([]string, 0, len(approvedRelPaths)),
		RejectedFiles:  make([]string, 0),
	}

	for _, rel := range approvedRelPaths {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}

		cleanRel := filepath.Clean(rel)
		if strings.HasPrefix(cleanRel, "..") || filepath.IsAbs(cleanRel) {
			report.RejectedFiles = append(report.RejectedFiles, rel)
			continue
		}

		srcPath := filepath.Join(upperDir, cleanRel)
		dstPath := filepath.Join(hostDir, cleanRel)

		srcInfo, err := os.Lstat(srcPath)
		if err != nil {
			report.RejectedFiles = append(report.RejectedFiles, rel)
			continue
		}

		// Create parent directory
		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return report, fmt.Errorf("failed to create directory for %s: %w", dstPath, err)
		}

		if srcInfo.IsDir() {
			_ = os.MkdirAll(dstPath, srcInfo.Mode().Perm())
			report.CommittedFiles = append(report.CommittedFiles, cleanRel)
			continue
		}

		// Atomic file copy
		bytesWritten, err := copyFileContents(srcPath, dstPath, srcInfo.Mode().Perm())
		if err != nil {
			return report, fmt.Errorf("failed to commit file %s: %w", cleanRel, err)
		}

		report.CommittedFiles = append(report.CommittedFiles, cleanRel)
		report.TotalBytes += bytesWritten
	}

	return report, nil
}

func copyFileContents(src, dst string, perm os.FileMode) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	// Write to temporary file first for atomic replacement
	tmpDst := fmt.Sprintf("%s.aegis_tmp", dst)
	out, err := os.OpenFile(tmpDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return 0, err
	}

	n, err := io.Copy(out, in)
	closeErr := out.Close()
	if err != nil {
		if remErr := os.Remove(tmpDst); remErr != nil && !os.IsNotExist(remErr) {
			_ = remErr // best-effort cleanup on failure
		}
		return 0, err
	}
	if closeErr != nil {
		if remErr := os.Remove(tmpDst); remErr != nil && !os.IsNotExist(remErr) {
			_ = remErr
		}
		return 0, closeErr
	}

	// Atomic rename
	if err := os.Rename(tmpDst, dst); err != nil {
		if remErr := os.Remove(tmpDst); remErr != nil && !os.IsNotExist(remErr) {
			_ = remErr
		}
		return 0, err
	}

	return n, nil
}
