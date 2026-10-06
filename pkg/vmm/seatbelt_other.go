//go:build !darwin

package vmm

import (
	"context"
	"os/exec"
)

// HasSeatbelt returns false on non-macOS platforms.
func HasSeatbelt() bool {
	return false
}

// GenerateSeatbeltProfile returns an empty string on non-macOS platforms.
func GenerateSeatbeltProfile(workspaceMount string) string {
	return ""
}

// WrapCommandWithSeatbelt falls back to regular sh -c on non-macOS platforms.
func WrapCommandWithSeatbelt(ctx context.Context, cmdStr string, workspaceMount string) *exec.Cmd {
	return exec.CommandContext(ctx, "sh", "-c", cmdStr)
}
