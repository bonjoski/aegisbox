//go:build !linux && !darwin && !windows

package bridge

import (
	"errors"
	"os"
	"unsafe"
)

func unsafePointer(p *byte) unsafe.Pointer {
	return unsafe.Pointer(p)
}

func createSharedMemoryFile(name string, size int64) (*os.File, []byte, error) {
	return nil, nil, errors.New("shm: unsupported operating system")
}

func mapExistingMemory(f *os.File, size int64) ([]byte, error) {
	return nil, errors.New("shm: unsupported operating system")
}

func unmapMemory(data []byte) error {
	return nil
}
