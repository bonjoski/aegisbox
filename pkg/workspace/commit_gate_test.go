package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommitSafeDiff_CleanFiles(t *testing.T) {
	upperDir := t.TempDir()
	hostDir := t.TempDir()

	// Write clean files to upper layer
	srcFile := filepath.Join(upperDir, "main.go")
	if err := os.WriteFile(srcFile, []byte("package main\n"), 0644); err != nil {
		t.Fatalf("failed to write src file: %v", err)
	}

	report, err := CommitSafeDiff(context.Background(), upperDir, hostDir, []string{"main.go"})
	if err != nil {
		t.Fatalf("CommitSafeDiff failed: %v", err)
	}

	if len(report.CommittedFiles) != 1 || report.CommittedFiles[0] != "main.go" {
		t.Errorf("expected main.go in committed files, got: %v", report.CommittedFiles)
	}

	// Verify file on host
	hostContent, err := os.ReadFile(filepath.Join(hostDir, "main.go"))
	if err != nil {
		t.Fatalf("failed to read committed host file: %v", err)
	}
	if string(hostContent) != "package main\n" {
		t.Errorf("host content mismatch: %s", string(hostContent))
	}
}

func TestCommitSafeDiff_SymlinkEscapeRejection(t *testing.T) {
	upperDir := t.TempDir()
	hostDir := t.TempDir()

	// Create malicious symlink targeting /etc/hosts outside the workspace
	escapedSymlink := filepath.Join(upperDir, "leaked_hosts")
	if err := os.Symlink("/etc/hosts", escapedSymlink); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	_, err := CommitSafeDiff(context.Background(), upperDir, hostDir, []string{"leaked_hosts"})
	if err == nil {
		t.Fatalf("expected CommitSafeDiff to reject escaping symlink, but got nil")
	}

	if !strings.Contains(err.Error(), "symlink targets a path outside") {
		t.Errorf("expected symlink escape error, got: %v", err)
	}
}
