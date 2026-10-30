//go:build !windows

package bridge

import (
	"fmt"
	"syscall"
)

// killProcessGroup sends the given signal to the target process group, falling back to PID.
func killProcessGroup(pgid int, pid int, sig syscall.Signal) error {
	var lastErr error

	// If a positive PGID is known, signal the entire process group with negative PID
	if pgid > 0 {
		if err := syscall.Kill(-pgid, sig); err == nil {
			return nil
		} else if err == syscall.ESRCH {
			// Process group already exited
			return nil
		} else {
			lastErr = err
		}
	}

	// Fallback to targeting the specific PID
	if pid > 0 {
		if err := syscall.Kill(pid, sig); err == nil {
			return nil
		} else if err == syscall.ESRCH {
			return nil
		} else {
			lastErr = err
		}
	}

	if lastErr != nil {
		return fmt.Errorf("failed to signal process group (pgid=%d, pid=%d, sig=%v): %w", pgid, pid, sig, lastErr)
	}
	return nil
}
