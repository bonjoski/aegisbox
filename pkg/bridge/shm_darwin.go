//go:build darwin

package bridge

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func unsafePointer(p *byte) unsafe.Pointer {
	return unsafe.Pointer(p)
}

func createSharedMemoryFile(name string, size int64) (*os.File, []byte, error) {
	// macOS / Darwin: Create anonymous temporary memory-backed descriptor
	f, err := os.CreateTemp("", "aegisbox-shm-*")
	if err != nil {
		return nil, nil, fmt.Errorf("shm: create temp failed: %w", err)
	}

	// Unlink immediately: inode remains allocated until file closed
	if rmErr := os.Remove(f.Name()); rmErr != nil && !os.IsNotExist(rmErr) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("shm: unlink temp file failed: %w", rmErr)
	}

	if err := unix.Ftruncate(int(f.Fd()), size); err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("shm: ftruncate memory file to %d failed: %w", size, err)
	}

	mmapData, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("shm: mmap failed: %w", err)
	}

	return f, mmapData, nil
}

func mapExistingMemory(f *os.File, size int64) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("shm: file descriptor is nil")
	}

	mmapData, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("shm: attach mmap failed: %w", err)
	}

	return mmapData, nil
}

func unmapMemory(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return unix.Munmap(data)
}
