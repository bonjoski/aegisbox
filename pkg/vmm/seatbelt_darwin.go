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
// restricting file reads to non-sensitive paths and developer toolchains,
// blocking access to host home and /tmp/cc-socks sockets,
// denying process table enumeration, and restricting file writes strictly to
// the shadow workspace and temporary buffers.
func GenerateSeatbeltProfile(workspaceMount string) string {
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/Users"
	}
	realHome, err := filepath.EvalSymlinks(home)
	if err != nil || realHome == "" {
		realHome = home
	}

	realWorkspaceMount, err := filepath.EvalSymlinks(workspaceMount)
	if err != nil || realWorkspaceMount == "" {
		realWorkspaceMount = workspaceMount
	}

	var sb strings.Builder
	sb.WriteString("(version 1)\n(allow default)\n\n")

	// 1. Deny inspecting other processes across system (pgrep, ps, sysctl KERN_PROC)
	sb.WriteString(";; Deny process table inspection across system\n")
	sb.WriteString("(deny process-info* (target others))\n\n")

	// 2. Deny reading host home directory
	sb.WriteString(";; Deny reading real host home directory\n")
	sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", home))
	if realHome != home {
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", realHome))
	}
	if !strings.HasPrefix(home, "/System/Volumes/Data") {
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", "/System/Volumes/Data"+home))
	}

	// Deny access to Claude Code messaging sockets and other IPC sockets in /tmp
	sb.WriteString("\n;; Deny reading/writing Claude Code messaging sockets and host IPC sockets\n")
	sb.WriteString("(deny file-read* (subpath \"/tmp/cc-socks\"))\n")
	sb.WriteString("(deny file-read* (subpath \"/private/tmp/cc-socks\"))\n")
	sb.WriteString("(deny file-write* (subpath \"/tmp/cc-socks\"))\n")
	sb.WriteString("(deny file-write* (subpath \"/private/tmp/cc-socks\"))\n")

	// 3. Re-allow reading workspace and safe developer runtimes
	sb.WriteString("\n;; Re-allow reading shadow workspace\n")
	sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", workspaceMount))
	if realWorkspaceMount != workspaceMount {
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", realWorkspaceMount))
	}

	sb.WriteString("\n;; Re-allow reading developer toolchains and runtimes in user profile\n")
	devDirs := []string{
		filepath.Join(home, ".cargo"),
		filepath.Join(home, ".rustup"),
		filepath.Join(home, ".nvm"),
		filepath.Join(home, ".local"),
		filepath.Join(home, ".pyenv"),
		filepath.Join(home, ".rbenv"),
		filepath.Join(home, ".asdf"),
		filepath.Join(home, ".bun"),
		filepath.Join(home, ".deno"),
		filepath.Join(home, "go"),
		filepath.Join(home, ".go"),
		filepath.Join(home, ".npm"),
		filepath.Join(home, ".yarn"),
		filepath.Join(home, ".pnpm-store"),
	}
	for _, d := range devDirs {
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", d))
		if realHome != home {
			rel, err := filepath.Rel(home, d)
			if err == nil {
				sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", filepath.Join(realHome, rel)))
			}
		}
	}

	// 4. Deny reading host credentials & sensitive configs (placed after dev toolchain allows)
	sensitivePaths := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".config"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".bash_history"),
		filepath.Join(home, ".git-credentials"),
		filepath.Join(home, ".npmrc"),
		filepath.Join(home, ".dockercfg"),
		filepath.Join(home, ".docker"),
		filepath.Join(home, ".cargo", "credentials"),
		filepath.Join(home, ".cargo", "credentials.toml"),
	}

	sb.WriteString("\n;; Explicitly deny reading sensitive host credentials, configs, and histories\n")
	for _, p := range sensitivePaths {
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", p))
		if realHome != home {
			rel, err := filepath.Rel(home, p)
			if err == nil {
				sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", filepath.Join(realHome, rel)))
			}
		}
		if !strings.HasPrefix(p, "/System/Volumes/Data") {
			sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %q))\n", "/System/Volumes/Data"+p))
		}
	}

	// 5. Restrict file writes: deny host home, /tmp, and /private/tmp; allow workspaceMount and isolated scratch
	sb.WriteString("\n;; Restrict file writes strictly to shadow workspace and scratch buffers\n")
	sb.WriteString(fmt.Sprintf("(deny file-write* (subpath %q))\n", home))
	if realHome != home {
		sb.WriteString(fmt.Sprintf("(deny file-write* (subpath %q))\n", realHome))
	}
	if !strings.HasPrefix(home, "/System/Volumes/Data") {
		sb.WriteString(fmt.Sprintf("(deny file-write* (subpath %q))\n", "/System/Volumes/Data"+home))
	}

	// Deny writing to shared host /tmp
	sb.WriteString("(deny file-write* (subpath \"/tmp\"))\n")
	sb.WriteString("(deny file-write* (subpath \"/private/tmp\"))\n")

	// Allow writes to workspace and macOS runtime scratch directories
	sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", workspaceMount))
	if realWorkspaceMount != workspaceMount {
		sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", realWorkspaceMount))
	}
	sb.WriteString("(allow file-write* (subpath \"/var/folders\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/private/var/folders\"))\n")

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
