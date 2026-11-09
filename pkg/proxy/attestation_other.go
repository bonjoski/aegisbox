//go:build !darwin && !linux

package proxy

import "fmt"

func platformProcessStartTime(pid int) (int64, error) {
	return 0, fmt.Errorf("%w: kernel peer attestation unsupported on this OS for pid %d", ErrAttestationPIDMismatch, pid)
}

func platformProcessExecutablePath(pid int) (string, error) {
	return "", fmt.Errorf("%w: kernel peer attestation unsupported on this OS for pid %d", ErrAttestationPIDMismatch, pid)
}
