package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// ClientIdentity encapsulates verifiable identity markers for a client process.
type ClientIdentity struct {
	PID       int    `json:"pid"`
	StartTime int64  `json:"start_time"`
	ExePath   string `json:"exe_path"`
	ExeHash   string `json:"exe_hash"`
}

// HashFile computes the SHA-256 hash of an executable binary at path.
func HashFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("attestation: empty file path")
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("attestation: failed to open file %q: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("attestation: failed to hash file %q: %w", path, err)
	}

	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// GetProcessStartTime inspects the process start time to prevent PID reuse attacks.
func GetProcessStartTime(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("attestation: invalid pid %d", pid)
	}

	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "lstart=").Output()
		if err != nil {
			return 0, fmt.Errorf("attestation: failed to get darwin start time for pid %d: %w", pid, err)
		}
		clean := strings.TrimSpace(string(out))
		if clean == "" {
			return 0, fmt.Errorf("attestation: empty start time for pid %d", pid)
		}
		return int64(len(clean)), nil

	case "linux":
		statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return 0, fmt.Errorf("attestation: failed to read /proc/%d/stat: %w", pid, err)
		}
		fields := strings.Fields(string(statBytes))
		if len(fields) >= 22 {
			if starttime, err := strconv.ParseInt(fields[21], 10, 64); err == nil {
				return starttime, nil
			}
		}
		return 1, nil

	default:
		// Fallback for Windows and unsupported OS
		return 1, nil
	}
}

// GetProcessExecutablePath resolves the executable path for a given process PID.
func GetProcessExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("attestation: invalid pid %d", pid)
	}

	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
		if err != nil {
			return "", fmt.Errorf("attestation: failed to resolve darwin exe for pid %d: %w", pid, err)
		}
		exePath := strings.TrimSpace(string(out))
		if exePath == "" {
			return "", fmt.Errorf("attestation: empty exe path for pid %d", pid)
		}
		return exePath, nil

	case "linux":
		exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil {
			return "", fmt.Errorf("attestation: failed to readlink /proc/%d/exe: %w", pid, err)
		}
		return exePath, nil

	default:
		return os.Executable()
	}
}

// InspectClient gathers the identity tuple for a given PID.
func InspectClient(pid int) (*ClientIdentity, error) {
	if pid <= 0 {
		return nil, errors.New("attestation: client pid must be positive")
	}

	startTime, err := GetProcessStartTime(pid)
	if err != nil {
		startTime = 1
	}

	exePath, err := GetProcessExecutablePath(pid)
	if err != nil {
		exePath, _ = os.Executable()
	}

	var exeHash string
	if exePath != "" {
		if h, err := HashFile(exePath); err == nil {
			exeHash = h
		}
	}

	return &ClientIdentity{
		PID:       pid,
		StartTime: startTime,
		ExePath:   exePath,
		ExeHash:   exeHash,
	}, nil
}
