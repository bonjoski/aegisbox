//go:build darwin

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

// HasSeatbelt returns true if macOS sandbox-exec is available on the system.
func HasSeatbelt() bool {
	_, err := exec.LookPath("sandbox-exec")
	return err == nil
}

// VerifyLocalSandboxPrerequisites fails closed if sandbox-exec is unavailable on macOS.
func VerifyLocalSandboxPrerequisites() error {
	if !HasSeatbelt() {
		return errors.New("sandbox-exec binary not found on macOS; refusing unconfined local execution")
	}
	return nil
}

// ValidateSBPLParam rejects control characters (NUL, CR, LF) in Seatbelt parameters or literals.
func ValidateSBPLParam(val string) error {
	if strings.ContainsAny(val, "\x00\r\n") {
		return errors.New("invalid control character (NUL/CR/LF) in Seatbelt path parameter")
	}
	return nil
}

// EscapeSBPLString validates against control characters and escapes backslashes and double quotes
// so dynamic path literals can never break out of SBPL S-expressions.
func EscapeSBPLString(val string) (string, error) {
	if err := ValidateSBPLParam(val); err != nil {
		return "", err
	}
	escaped := strings.ReplaceAll(val, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return escaped, nil
}

func resolveSeatbeltPaths(workspaceMount string) (home, realHome, ws, realWS string, err error) {
	if err := ValidateSBPLParam(workspaceMount); err != nil {
		return "", "", "", "", err
	}
	home, _ = os.UserHomeDir()
	if home == "" {
		home = "/Users"
	}
	if err := ValidateSBPLParam(home); err != nil {
		return "", "", "", "", err
	}

	realHome, evalErr := filepath.EvalSymlinks(home)
	if evalErr != nil || realHome == "" {
		realHome = home
	}
	if err := ValidateSBPLParam(realHome); err != nil {
		return "", "", "", "", err
	}

	ws = workspaceMount
	realWS, evalErr = filepath.EvalSymlinks(workspaceMount)
	if evalErr != nil || realWS == "" {
		realWS = workspaceMount
	}
	if err := ValidateSBPLParam(realWS); err != nil {
		return "", "", "", "", err
	}
	return home, realHome, ws, realWS, nil
}

// GenerateSeatbeltProfile creates an escaped SBPL profile restricting file reads/writes.
// If workspaceMount contains illegal control characters, it fails closed with (deny default).
func GenerateSeatbeltProfile(workspaceMount string, airgap ...bool) string {
	isAirgap := len(airgap) > 0 && airgap[0]
	home, realHome, ws, realWS, err := resolveSeatbeltPaths(workspaceMount)
	if err != nil {
		return "(version 1)\n(deny default)\n"
	}

	escHome, err := EscapeSBPLString(home)
	if err != nil {
		return "(version 1)\n(deny default)\n"
	}
	escRealHome, err := EscapeSBPLString(realHome)
	if err != nil {
		return "(version 1)\n(deny default)\n"
	}
	escWS, err := EscapeSBPLString(ws)
	if err != nil {
		return "(version 1)\n(deny default)\n"
	}
	escRealWS, err := EscapeSBPLString(realWS)
	if err != nil {
		return "(version 1)\n(deny default)\n"
	}

	return buildSBPLProfile(escHome, escRealHome, escWS, escRealWS, false, isAirgap)
}

// GenerateParameterizedSeatbeltProfile returns an SBPL profile referencing -D parameters
// (WORKSPACE_MOUNT, REAL_WORKSPACE_MOUNT, HOME_DIR, REAL_HOME_DIR) alongside the validated parameter map.
func GenerateParameterizedSeatbeltProfile(workspaceMount string, airgap ...bool) (string, map[string]string, error) {
	isAirgap := len(airgap) > 0 && airgap[0]
	home, realHome, ws, realWS, err := resolveSeatbeltPaths(workspaceMount)
	if err != nil {
		return "", nil, err
	}

	params := map[string]string{
		"HOME_DIR":             home,
		"REAL_HOME_DIR":        realHome,
		"WORKSPACE_MOUNT":      ws,
		"REAL_WORKSPACE_MOUNT": realWS,
	}

	profile := buildSBPLProfile(home, realHome, ws, realWS, true, isAirgap)
	return profile, params, nil
}

func sbplExpr(rawOrEscaped string, isParam bool, paramName string) string {
	if isParam {
		return fmt.Sprintf(`(param "%s")`, paramName)
	}
	return fmt.Sprintf(`"%s"`, rawOrEscaped)
}

func sbplJoinExpr(baseEscaped string, isParam bool, paramName string, suffix string) string {
	escSuffix, err := EscapeSBPLString(suffix)
	if err != nil {
		return `"/nonexistent"`
	}
	if isParam {
		return fmt.Sprintf(`(string-append (param "%s") "%s")`, paramName, escSuffix)
	}
	return fmt.Sprintf(`"%s%s"`, baseEscaped, escSuffix)
}

func buildSBPLProfile(home, realHome, ws, realWS string, parameterized bool, isAirgap bool) string {
	var sb strings.Builder
	sb.WriteString("(version 1)\n(allow default)\n\n")

	if isAirgap {
		sb.WriteString(";; Airgap mode: sever all outbound network egress and sinkhole DNS\n")
		sb.WriteString("(deny network-outbound)\n")
		sb.WriteString(";; Allow loopback only for local credential proxy and IPC\n")
		sb.WriteString("(allow network* (local ip \"localhost:*\"))\n")
		sb.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n\n")
	}

	// 1. Deny inspecting other processes across system (pgrep, ps, sysctl KERN_PROC)
	sb.WriteString(";; Deny process table inspection across system\n")
	sb.WriteString("(deny process-info* (target others))\n")
	sb.WriteString("(deny file-ioctl (literal \"/dev/tty\"))\n\n")

	// 2. Deny reading host home directory first, then selectively re-allow safe runtimes
	sb.WriteString(";; Deny reading real host home directory\n")
	sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %s))\n", sbplExpr(home, parameterized, "HOME_DIR")))
	if realHome != home {
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath %s))\n", sbplExpr(realHome, parameterized, "REAL_HOME_DIR")))
	}
	if !strings.HasPrefix(home, "/System/Volumes/Data") {
		if parameterized {
			sb.WriteString(`(deny file-read* (subpath (string-append "/System/Volumes/Data" (param "HOME_DIR"))))` + "\n")
		} else {
			sb.WriteString(fmt.Sprintf("(deny file-read* (subpath \"/System/Volumes/Data%s\"))\n", home))
		}
	}

	// 3. Re-allow reading shadow workspace and safe developer runtimes
	if ws != "" {
		sb.WriteString("\n;; Re-allow reading shadow workspace\n")
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %s))\n", sbplExpr(ws, parameterized, "WORKSPACE_MOUNT")))
		if realWS != ws {
			sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %s))\n", sbplExpr(realWS, parameterized, "REAL_WORKSPACE_MOUNT")))
		}
	}

	sb.WriteString("\n;; Re-allow reading developer toolchains and runtimes in user profile\n")
	devSuffixes := []string{
		"/.cargo", "/.rustup", "/.nvm", "/.local", "/.pyenv",
		"/.rbenv", "/.asdf", "/.bun", "/.deno", "/go",
		"/.go", "/.npm", "/.yarn", "/.pnpm-store",
	}
	for _, sfx := range devSuffixes {
		sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %s))\n", sbplJoinExpr(home, parameterized, "HOME_DIR", sfx)))
		if realHome != home {
			sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %s))\n", sbplJoinExpr(realHome, parameterized, "REAL_HOME_DIR", sfx)))
		}
	}

	// 4. Restrict file writes: deny host home and /tmp, allow workspaceMount and runtime scratch
	sb.WriteString("\n;; Restrict file writes strictly to shadow workspace and scratch buffers\n")
	sb.WriteString(fmt.Sprintf("(deny file-write* (subpath %s))\n", sbplExpr(home, parameterized, "HOME_DIR")))
	if realHome != home {
		sb.WriteString(fmt.Sprintf("(deny file-write* (subpath %s))\n", sbplExpr(realHome, parameterized, "REAL_HOME_DIR")))
	}
	if !strings.HasPrefix(home, "/System/Volumes/Data") {
		if parameterized {
			sb.WriteString(`(deny file-write* (subpath (string-append "/System/Volumes/Data" (param "HOME_DIR"))))` + "\n")
		} else {
			sb.WriteString(fmt.Sprintf("(deny file-write* (subpath \"/System/Volumes/Data%s\"))\n", home))
		}
	}
	sb.WriteString("(deny file-write* (subpath \"/tmp\"))\n")
	sb.WriteString("(deny file-write* (subpath \"/private/tmp\"))\n")

	if ws != "" {
		sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %s))\n", sbplExpr(ws, parameterized, "WORKSPACE_MOUNT")))
		if realWS != ws {
			sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %s))\n", sbplExpr(realWS, parameterized, "REAL_WORKSPACE_MOUNT")))
		}
	}
	sb.WriteString("(allow file-write* (subpath \"/var/folders\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/private/var/folders\"))\n")

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

	// 5. Specific DENY rules placed strictly AFTER all allow rules so denials always win!
	sb.WriteString("\n;; Deny reading/writing Claude Code messaging sockets and host Aegisbox/Argus/Fabrial IPC\n")
	sb.WriteString("(deny file-read* file-write* (subpath \"/tmp/cc-socks\"))\n")
	sb.WriteString("(deny file-read* file-write* (subpath \"/private/tmp/cc-socks\"))\n")

	sensitiveSuffixes := []string{
		"/.ssh", "/.aws", "/.gnupg", "/.config", "/.kube",
		"/.fabrial", "/.aegisbox", "/.argus", "/.locksmith",
		"/.netrc", "/.zsh_history", "/.bash_history",
		"/.git-credentials", "/.npmrc", "/.pypirc",
		"/.dockercfg", "/.docker",
		"/.cargo/credentials", "/.cargo/credentials.toml",
	}
	sb.WriteString("\n;; Explicitly deny reading/writing sensitive host credentials, configs, and histories\n")
	for _, sfx := range sensitiveSuffixes {
		sb.WriteString(fmt.Sprintf("(deny file-read* file-write* file-link (subpath %s))\n", sbplJoinExpr(home, parameterized, "HOME_DIR", sfx)))
		if realHome != home {
			sb.WriteString(fmt.Sprintf("(deny file-read* file-write* file-link (subpath %s))\n", sbplJoinExpr(realHome, parameterized, "REAL_HOME_DIR", sfx)))
		}
		if !strings.HasPrefix(home, "/System/Volumes/Data") {
			if parameterized {
				escSfx, _ := EscapeSBPLString(sfx)
				sb.WriteString(fmt.Sprintf(`(deny file-read* file-write* file-link (subpath (string-append "/System/Volumes/Data" (param "HOME_DIR") "%s")))`+"\n", escSfx))
			} else {
				escSfx, _ := EscapeSBPLString(sfx)
				sb.WriteString(fmt.Sprintf("(deny file-read* file-write* file-link (subpath \"/System/Volumes/Data%s%s\"))\n", home, escSfx))
			}
		}
	}

	if ws != "" {
		sb.WriteString("\n;; Protect .git hooks/config inside shadow workspace from tampering\n")
		sb.WriteString(fmt.Sprintf("(deny file-write* file-link (subpath %s))\n", sbplJoinExpr(ws, parameterized, "WORKSPACE_MOUNT", "/.git/hooks")))
		if realWS != ws {
			sb.WriteString(fmt.Sprintf("(deny file-write* file-link (subpath %s))\n", sbplJoinExpr(realWS, parameterized, "REAL_WORKSPACE_MOUNT", "/.git/hooks")))
		}
	}

	return sb.String()
}

// WrapArgvWithSeatbelt wraps structured argv directly with parameterized macOS sandbox-exec.
// AEGISBOX_NO_SEATBELT is intentionally NOT supported; fails closed if sandbox-exec is absent or paths are invalid.
func WrapArgvWithSeatbelt(ctx context.Context, argv []string, workspaceMount string, airgap ...bool) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, errors.New("empty command argv")
	}
	if !HasSeatbelt() {
		return nil, errors.New("sandbox-exec unavailable on macOS; refusing unconfined execution")
	}

	profile, params, err := GenerateParameterizedSeatbeltProfile(workspaceMount, airgap...)
	if err != nil {
		return nil, fmt.Errorf("invalid seatbelt parameters: %w", err)
	}

	execArgs := []string{
		"-D", "HOME_DIR=" + params["HOME_DIR"],
		"-D", "REAL_HOME_DIR=" + params["REAL_HOME_DIR"],
		"-D", "WORKSPACE_MOUNT=" + params["WORKSPACE_MOUNT"],
		"-D", "REAL_WORKSPACE_MOUNT=" + params["REAL_WORKSPACE_MOUNT"],
		"-p", profile,
		"--",
	}
	execArgs = append(execArgs, argv...)
	return exec.CommandContext(ctx, "sandbox-exec", execArgs...), nil
}

// WrapCommandWithSeatbelt wraps a shell command string with parameterized macOS sandbox-exec.
// Fails closed (invoking /usr/bin/false) if sandbox-exec is unavailable or workspaceMount contains control characters.
func WrapCommandWithSeatbelt(ctx context.Context, cmdStr string, workspaceMount string, airgap ...bool) *exec.Cmd {
	cmd, err := WrapArgvWithSeatbelt(ctx, []string{"/bin/sh", "-c", cmdStr}, workspaceMount, airgap...)
	if err != nil {
		return exec.CommandContext(ctx, "/usr/bin/false")
	}
	return cmd
}
