//go:build windows

package pty

import (
	"errors"
	"os"
)

// CheckTIOCSTI is a no-op on Windows where TIOCSTI ioctls do not exist in the console subsystem.
func CheckTIOCSTI(f *os.File) error {
	if f == nil {
		return errors.New("pty: file descriptor is nil")
	}
	return nil
}
