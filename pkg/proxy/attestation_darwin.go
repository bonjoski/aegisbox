//go:build darwin

package proxy

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	darwinProcInfoCallPIDInfo = 2
	darwinProcPIDPathInfo     = 11
	darwinProcPIDPathMaxSize  = 4096
)

func platformProcessStartTime(pid int) (int64, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, fmt.Errorf("%w: sysctl kern.proc.pid(%d) failed: %w", ErrAttestationPIDMismatch, pid, err)
	}
	if int(kp.Proc.P_pid) != pid {
		return 0, fmt.Errorf("%w: kinfo_proc pid mismatch (%d != %d)", ErrAttestationPIDMismatch, kp.Proc.P_pid, pid)
	}
	ns := kp.Proc.P_starttime.Nano()
	if ns <= 0 {
		return 0, fmt.Errorf("%w: invalid zero start time for pid %d", ErrAttestationPIDMismatch, pid)
	}
	return ns, nil
}

func platformProcessExecutablePath(pid int) (string, error) {
	buf := make([]byte, darwinProcPIDPathMaxSize)
	_, _, errno := unix.Syscall6(
		unix.SYS_PROC_INFO,
		uintptr(darwinProcInfoCallPIDInfo),
		uintptr(pid),
		uintptr(darwinProcPIDPathInfo),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return "", fmt.Errorf("%w: proc_pidpath(%d) failed: %w", ErrAttestationPIDMismatch, pid, errno)
	}
	exePath := unix.ByteSliceToString(buf)
	if exePath == "" {
		return "", fmt.Errorf("%w: empty vnode path for pid %d", ErrAttestationPIDMismatch, pid)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil && resolved != "" {
		return resolved, nil
	}
	return exePath, nil
}
