//go:build linux

package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func platformProcessStartTime(pid int) (int64, error) {
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("%w: failed reading /proc/%d/stat: %w", ErrAttestationPIDMismatch, pid, err)
	}
	raw := string(statBytes)
	closeParen := strings.LastIndexByte(raw, ')')
	if closeParen == -1 || closeParen+2 >= len(raw) {
		return 0, fmt.Errorf("%w: malformed /proc/%d/stat payload", ErrAttestationPIDMismatch, pid)
	}
	// Fields after "(comm) ": index 0 is field 3 (state), so index 19 is field 22 (starttime).
	fields := strings.Fields(raw[closeParen+2:])
	if len(fields) <= 19 {
		return 0, fmt.Errorf("%w: truncated /proc/%d/stat payload", ErrAttestationPIDMismatch, pid)
	}
	startTicks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil || startTicks <= 0 {
		return 0, fmt.Errorf("%w: invalid starttime field in /proc/%d/stat", ErrAttestationPIDMismatch, pid)
	}
	return startTicks, nil
}

func platformProcessExecutablePath(pid int) (string, error) {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", fmt.Errorf("%w: failed reading /proc/%d/exe: %w", ErrAttestationPIDMismatch, pid, err)
	}
	if strings.HasSuffix(exePath, " (deleted)") {
		return "", fmt.Errorf("%w: process %d executable has been unlinked (%s)", ErrAttestationPIDMismatch, pid, exePath)
	}
	if resolved, rErr := filepath.EvalSymlinks(exePath); rErr == nil && resolved != "" {
		return resolved, nil
	}
	return exePath, nil
}
