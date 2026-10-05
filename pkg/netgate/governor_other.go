//go:build !darwin && !linux && !windows

package netgate

func newPlatformGovernor() NetworkGovernor {
	return NewMemoryGovernor()
}
