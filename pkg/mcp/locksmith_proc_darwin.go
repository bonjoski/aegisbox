//go:build darwin

package mcp

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// getProcessStartTime queries the Darwin kernel process start timestamp in nanoseconds via sysctl.
func getProcessStartTime(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	if kp == nil || int(kp.Proc.P_pid) != pid {
		return 0, fmt.Errorf("pid %d not found", pid)
	}
	ns := kp.Proc.P_starttime.Nano()
	if ns <= 0 {
		return 0, fmt.Errorf("invalid kernel start timestamp for pid %d", pid)
	}
	return ns, nil
}
