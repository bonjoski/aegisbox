package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// ClientIdentity encapsulates verifiable kernel-attested identity markers for a client process.
type ClientIdentity struct {
	PID       int    `json:"pid"`
	StartTime int64  `json:"start_time"`
	ExePath   string `json:"exe_path"`
	ExeHash   string `json:"exe_hash"`
}

var (
	// ErrAttestationHashMismatch indicates that the client executable has been modified or spoofed.
	ErrAttestationHashMismatch = errors.New("attestation: binary hash mismatch")
	// ErrAttestationPIDMismatch indicates that the target PID failed verification.
	ErrAttestationPIDMismatch = errors.New("attestation: process identity mismatch")
)

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

// GetProcessStartTime queries the kernel directly for the nanosecond/tick process creation timestamp
// to prevent PID reuse spoofing without spawning any child `ps` subprocess.
func GetProcessStartTime(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("%w: invalid pid %d", ErrAttestationPIDMismatch, pid)
	}
	return platformProcessStartTime(pid)
}

// GetProcessExecutablePath resolves the kernel vnode executable path for a given process PID
// without reading spoofable `argv[0]` / `ps -o comm=`.
func GetProcessExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("%w: invalid pid %d", ErrAttestationPIDMismatch, pid)
	}
	return platformProcessExecutablePath(pid)
}

// InspectClient gathers the kernel-verified identity tuple for a given PID.
// Fails closed if any kernel attribute or binary hash cannot be verified; NEVER falls back to os.Executable().
func InspectClient(pid int) (*ClientIdentity, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("%w: client pid must be positive (got %d)", ErrAttestationPIDMismatch, pid)
	}

	startTime, err := GetProcessStartTime(pid)
	if err != nil {
		return nil, fmt.Errorf("attestation: start-time inspection failed for pid %d: %w", pid, err)
	}
	if startTime <= 0 {
		return nil, fmt.Errorf("%w: non-positive start time for pid %d", ErrAttestationPIDMismatch, pid)
	}

	exePath, err := GetProcessExecutablePath(pid)
	if err != nil {
		return nil, fmt.Errorf("attestation: executable path inspection failed for pid %d: %w", pid, err)
	}

	exeHash, err := HashFile(exePath)
	if err != nil {
		return nil, fmt.Errorf("attestation: executable hash failed for pid %d (%s): %w", pid, exePath, err)
	}

	return &ClientIdentity{
		PID:       pid,
		StartTime: startTime,
		ExePath:   exePath,
		ExeHash:   exeHash,
	}, nil
}

// VerifyIdentity verifies that the inspected client matches the expected cryptographic hash.
func (c *ClientIdentity) VerifyIdentity(expectedHash string) error {
	if c == nil {
		return errors.New("attestation: nil client identity")
	}
	if expectedHash != "" && c.ExeHash != expectedHash {
		return fmt.Errorf("%w: expected %q, got %q", ErrAttestationHashMismatch, expectedHash, c.ExeHash)
	}
	return nil
}

// AttestClient inspects the client PID and cryptographically validates its binary hash.
func AttestClient(pid int, expectedHash string) (*ClientIdentity, error) {
	id, err := InspectClient(pid)
	if err != nil {
		return nil, err
	}
	if err := id.VerifyIdentity(expectedHash); err != nil {
		return nil, err
	}
	return id, nil
}
