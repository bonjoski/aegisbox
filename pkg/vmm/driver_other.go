//go:build !darwin && !linux && !windows

package vmm

func newPlatformDriver() HypervisorDriver {
	return NewLocalProcessDriver()
}

