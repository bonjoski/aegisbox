//go:build windows

package bridge

import (
	"fmt"
	"os"
	"syscall"
)

// killProcessGroup sends the given signal or terminates the process on Windows.
func killProcessGroup(pgid int, pid int, sig syscall.Signal) error {
	target := pid
	if target <= 0 {
		target = pgid
	}
	if target <= 0 {
		return nil
	}

	proc, err := os.FindProcess(target)
	if err != nil {
		return nil
	}
	if err := proc.Kill(); err != nil {
		return fmt.Errorf("failed to terminate process (pid=%d): %w", target, err)
	}
	return nil
}
