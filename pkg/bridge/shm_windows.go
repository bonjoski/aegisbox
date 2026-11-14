//go:build windows

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
	// Heap-backed emulation on Windows without vhost-user
	data := make([]byte, size)
	return nil, data, nil
}

func mapExistingMemory(f *os.File, size int64) ([]byte, error) {
	return nil, errors.New("shm: vhost-user not supported on windows")
}

func unmapMemory(data []byte) error {
	return nil
}
