//go:build windows

package vmm

// FlushVirtiofsCache is a no-op on Windows.
func FlushVirtiofsCache() {}
