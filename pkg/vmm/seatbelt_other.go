//go:build !darwin

package vmm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// HasSeatbelt returns false on non-macOS platforms.
func HasSeatbelt() bool {
	return false
}

// ValidateSBPLParam rejects control characters (NUL, CR, LF) in sandbox path parameters.
func ValidateSBPLParam(val string) error {
	if strings.ContainsAny(val, "\x00\r\n") {
		return errors.New("invalid control character (NUL/CR/LF) in sandbox path parameter")
	}
	return nil
}

// EscapeSBPLString validates against control characters and escapes backslashes and double quotes.
func EscapeSBPLString(val string) (string, error) {
	if err := ValidateSBPLParam(val); err != nil {
		return "", err
	}
	escaped := strings.ReplaceAll(val, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return escaped, nil
}

// GenerateSeatbeltProfile returns an empty string on non-macOS platforms.
func GenerateSeatbeltProfile(workspaceMount string, airgap ...bool) string {
	return ""
}

// GenerateParameterizedSeatbeltProfile returns an error on non-macOS platforms.
func GenerateParameterizedSeatbeltProfile(workspaceMount string, airgap ...bool) (string, map[string]string, error) {
	return "", nil, errors.New("seatbelt profiles are only supported on darwin")
}

// VerifyLocalSandboxPrerequisites ensures hardened local confinement (airlock or bwrap) is installed on Linux/non-Darwin.
func VerifyLocalSandboxPrerequisites() error {
	if _, err := DiscoverAirlock(); err == nil {
		return nil
	}
	if _, err := exec.LookPath("bwrap"); err == nil {
		return nil
	}
	return errors.New("degraded local sandbox unavailable: neither airlock nor bwrap is installed on this host (refusing unconfined execution)")
}

// WrapArgvWithSeatbelt confines structured argv on Linux/non-Darwin using Airlock or Bubblewrap (bwrap),
// failing closed if neither confinement runtime is available.
func WrapArgvWithSeatbelt(ctx context.Context, argv []string, workspaceMount string, airgap ...bool) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command argv")
	}
	if err := ValidateSBPLParam(workspaceMount); err != nil {
		return nil, err
	}
	isAirgap := len(airgap) > 0 && airgap[0]

	if airlockBin, err := DiscoverAirlock(); err == nil {
		var args []string
		if isAirgap {
			args = append(args, "--airgap")
		} else {
			args = append(args, "--profile", "agent")
		}
		args = append(args, "--")
		args = append(args, argv...)
		return exec.CommandContext(ctx, airlockBin, args...), nil
	}

	if bwrapBin, err := exec.LookPath("bwrap"); err == nil {
		args := []string{
			"--ro-bind", "/", "/",
			"--dev", "/dev",
			"--proc", "/proc",
			"--tmpfs", "/tmp",
			"--unshare-pid",
			"--unshare-ipc",
			"--unshare-uts",
			"--die-with-parent",
		}
		if isAirgap {
			args = append(args, "--unshare-net")
		}
		if home, hErr := os.UserHomeDir(); hErr == nil && home != "" {
			sensitive := []string{
				".ssh", ".aws", ".gnupg", ".kube", ".config",
				".fabrial", ".aegisbox", ".argus", ".locksmith", ".docker",
			}
			for _, sfx := range sensitive {
				target := filepath.Join(home, sfx)
				if fi, stErr := os.Stat(target); stErr == nil && fi.IsDir() {
					args = append(args, "--tmpfs", target)
				}
			}
		}
		if workspaceMount != "" {
			args = append(args, "--bind", workspaceMount, workspaceMount, "--chdir", workspaceMount)
		}
		args = append(args, "--")
		args = append(args, argv...)
		return exec.CommandContext(ctx, bwrapBin, args...), nil
	}

	return nil, fmt.Errorf("refusing unconfined local execution: neither airlock nor bwrap is installed")
}

// WrapCommandWithSeatbelt wraps a command string with Airlock or bwrap on non-macOS platforms,
// failing closed if neither confinement runtime is available.
func WrapCommandWithSeatbelt(ctx context.Context, cmdStr string, workspaceMount string, airgap ...bool) *exec.Cmd {
	cmd, err := WrapArgvWithSeatbelt(ctx, []string{"/bin/sh", "-c", cmdStr}, workspaceMount, airgap...)
	if err != nil {
		return exec.CommandContext(ctx, "/nonexistent-aegisbox-fail-closed-sandbox-unavailable")
	}
	return cmd
}
