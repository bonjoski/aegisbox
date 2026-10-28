//go:build darwin

package pty

import (
	"os"
	"syscall"
	"unsafe"
)

// IsTerminal returns true if the provided file descriptor is attached to an interactive terminal on macOS.
func (d *POSIXDetector) IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fd := f.Fd()

	var termios syscall.Termios
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		uintptr(syscall.TIOCGETA),
		uintptr(unsafe.Pointer(&termios)),
	)
	return err == 0
}
