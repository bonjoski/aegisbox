//go:build !darwin && !linux

package vmm

func newPlatformDriver() HypervisorDriver {
	return NewLocalProcessDriver()
}
