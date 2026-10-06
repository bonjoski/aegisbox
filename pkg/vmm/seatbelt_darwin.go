//go:build darwin

package vmm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// HasSeatbelt returns true if macOS sandbox-exec is available on the system.
func HasSeatbelt() bool {
	_, err := exec.LookPath("sandbox-exec")
	return err == nil
}

// GenerateSeatbeltProfile creates an SBPL (Seatbelt Profile Language) profile
// restricting file reads to non-sensitive paths and file writes strictly to
// the shadow workspace and temporary buffers.
func GenerateSeatbeltProfile(workspaceMount string) string {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/Users"
	}

	var sb strings.Builder
	sb.WriteString("(version 1)\n(allow default)\n\n")

	// 1. Deny reading host credentials & sensitive configs
	sensitiveDirs := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".config", "gh"),
		filepath.Join(home, ".config", "gcloud"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".bash_history"),
	}

	sb.WriteString(";; Deny reading sensitive host credentials and histories\n")
	for _, p := range sensitiveDirs {
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", p))
		if !strings.HasPrefix(p, "/System/Volumes/Data") {
			sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", "/System/Volumes/Data"+p))
		}
	}

	// 2. Deny writing to host home directory outside the shadow workspace
	sb.WriteString("\n;; Restrict file writes strictly to shadow workspace and scratch buffers\n")
	sb.WriteString(fmt.Sprintf("(deny file-write* (subpath %q))\n", home))
	if !strings.HasPrefix(home, "/System/Volumes/Data") {
		sb.WriteString(fmt.Sprintf("(deny file-write* (subpath %q))\n", "/System/Volumes/Data"+home))
	}

	allowedWrites := []string{
		workspaceMount,
		"/tmp",
		"/private/tmp",
		"/var/folders",
		"/private/var/folders",
	}

	for _, w := range allowedWrites {
		sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", w))
	}

	// Allow writes to terminal descriptors and standard devices
	sb.WriteString(`(allow file-write*
    (literal "/dev/null")
    (literal "/dev/zero")
    (literal "/dev/stdout")
    (literal "/dev/stderr")
    (literal "/dev/tty")
    (literal "/dev/ptmx")
    (regex #"^/dev/ttys.*$")
    (regex #"^/dev/fd/.*$")
)
`)

	return sb.String()
}

// WrapCommandWithSeatbelt wraps an exec.Cmd on macOS with sandbox-exec if available.
func WrapCommandWithSeatbelt(ctx context.Context, cmdStr string, workspaceMount string) *exec.Cmd {
	if HasSeatbelt() && os.Getenv("AEGISBOX_NO_SEATBELT") == "" {
		profile := GenerateSeatbeltProfile(workspaceMount)
		return exec.CommandContext(ctx, "sandbox-exec", "-p", profile, "sh", "-c", cmdStr)
	}
	return exec.CommandContext(ctx, "sh", "-c", cmdStr)
}
