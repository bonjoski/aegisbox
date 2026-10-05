package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSafePathGuard_TraversalDetection(t *testing.T) {
	tmpDir := t.TempDir()
	guard, err := NewSafePathGuard(tmpDir)
	if err != nil {
		t.Fatalf("NewSafePathGuard failed: %v", err)
	}

	traversalPaths := []string{
		"../outside.txt",
		"../../etc/passwd",
		"foo/../../bar/../../escape",
		"/etc/shadow",
	}

	for _, p := range traversalPaths {
		_, err := guard.ValidateRelativePath(p)
		if err == nil {
			t.Errorf("expected error for traversal path %q, got nil", p)
		}
	}

	validPaths := []string{
		"foo.txt",
		"src/main.go",
		"sub/dir/../dir/file.txt",
	}

	for _, p := range validPaths {
		resolved, err := guard.ValidateRelativePath(p)
		if err != nil {
			t.Errorf("unexpected error for valid path %q: %v", p, err)
		}
		if resolved == "" {
			t.Errorf("empty resolved path for %q", p)
		}
	}
}

func TestSafePathGuard_SymlinkEscapeDetection(t *testing.T) {
	tmpDir := t.TempDir()
	outsideDir := t.TempDir()

	secretFile := filepath.Join(outsideDir, "secret.key")
	if err := os.WriteFile(secretFile, []byte("super-secret-ssh-key"), 0600); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	guard, err := NewSafePathGuard(tmpDir)
	if err != nil {
		t.Fatalf("NewSafePathGuard failed: %v", err)
	}

	// 1. Create a malicious symlink pointing outside the workspace
	maliciousLink := filepath.Join(tmpDir, "stolen_key.txt")
	if err := os.Symlink(secretFile, maliciousLink); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	isSymlink, err := guard.InspectFile("stolen_key.txt")
	if !isSymlink {
		t.Errorf("expected isSymlink=true")
	}
	if err == nil {
		t.Errorf("expected error for symlink pointing outside workspace, got nil")
	}

	// 2. Create a benign internal symlink
	internalTarget := filepath.Join(tmpDir, "internal.txt")
	if err := os.WriteFile(internalTarget, []byte("hello internal"), 0644); err != nil {
		t.Fatalf("failed to write internal target: %v", err)
	}
	benignLink := filepath.Join(tmpDir, "link_to_internal.txt")
	if err := os.Symlink(internalTarget, benignLink); err != nil {
		t.Fatalf("failed to create benign symlink: %v", err)
	}

	isSymlink, err = guard.InspectFile("link_to_internal.txt")
	if !isSymlink {
		t.Errorf("expected isSymlink=true")
	}
	if err != nil {
		t.Errorf("unexpected error for benign internal symlink: %v", err)
	}
}

func TestSafeCopyFile_RefuseSymlinkAndQuota(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	symlinkPath := filepath.Join(srcDir, "link.txt")
	if err := os.Symlink("/etc/passwd", symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	dstFile := filepath.Join(dstDir, "target.txt")
	err := SafeCopyFile(symlinkPath, dstFile, 1024*1024)
	if err == nil {
		t.Errorf("expected error refusing to copy symlink, got nil")
	}

	// Test regular copy within quota
	regularFile := filepath.Join(srcDir, "valid.txt")
	if err := os.WriteFile(regularFile, []byte("sample content"), 0644); err != nil {
		t.Fatalf("failed to write regular file: %v", err)
	}

	dstValid := filepath.Join(dstDir, "valid.txt")
	if err := SafeCopyFile(regularFile, dstValid, 1024*1024); err != nil {
		t.Fatalf("unexpected error copying valid file: %v", err)
	}

	// Test quota overflow
	bigFile := filepath.Join(srcDir, "big.txt")
	if err := os.WriteFile(bigFile, make([]byte, 2048), 0644); err != nil {
		t.Fatalf("failed to write big file: %v", err)
	}
	dstBig := filepath.Join(dstDir, "big.txt")
	err = SafeCopyFile(bigFile, dstBig, 1024) // max 1024 bytes
	if err == nil {
		t.Errorf("expected error for file exceeding quota, got nil")
	}
}
