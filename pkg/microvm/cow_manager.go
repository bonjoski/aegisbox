package microvm

import (
	"context"

	"github.com/bonjoski/aegisbox/pkg/vmm"
)

// COWManager delegates to vmm.COWManager for microVM copy-on-write workspace cleanup.
type COWManager = vmm.COWManager

// NewCOWManager creates a new COWManager.
func NewCOWManager() *COWManager {
	return vmm.NewCOWManager()
}

// FlushVirtiofsCache drops virtiofs page cache entries across ephemeral COW snapshots.
func FlushVirtiofsCache() {
	vmm.FlushVirtiofsCache()
}

// PurgeWorktreeCache drops virtiofs caches and unmounts temporary COW overlay mounts.
func PurgeWorktreeCache(ctx context.Context, mountPoint string) error {
	return vmm.GetDefaultCOWManager().TeardownMount(ctx, mountPoint)
}
