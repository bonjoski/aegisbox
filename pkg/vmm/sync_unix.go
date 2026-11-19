//go:build !windows

package vmm

import (
	"os"

	"golang.org/x/sys/unix"
)

// FlushVirtiofsCache syncs filesystem pagecaches and drops virtiofs caches.
func FlushVirtiofsCache() {
	unix.Sync()
	// On Linux, purge dirty pagecache, dentries and inodes
	_ = os.WriteFile("/proc/sys/vm/drop_caches", []byte("3\n"), 0644)
}
