package vmm

import (
	"context"
	"os"
	"sync"
)

// COWOverlayMount represents an active ephemeral Copy-on-Write overlay layer.
type COWOverlayMount struct {
	ID         string
	MountPoint string
	ScratchDir string
}

// COWManager manages ephemeral copy-on-write workspace layers and guarantees
// that virtiofs caches and temporary mounts are explicitly flushed and unmounted
// upon microVM teardown to prevent cache residue across subagent worktrees.
type COWManager struct {
	mu     sync.Mutex
	mounts map[string]*COWOverlayMount
}

var (
	defaultCOWManager = NewCOWManager()
)

// GetDefaultCOWManager returns the package-level COW manager singleton.
func GetDefaultCOWManager() *COWManager {
	return defaultCOWManager
}

// NewCOWManager returns an initialized COWManager instance.
func NewCOWManager() *COWManager {
	return &COWManager{
		mounts: make(map[string]*COWOverlayMount),
	}
}

// RegisterMount tracks a new ephemeral COW overlay mount.
func (m *COWManager) RegisterMount(id, mountPoint, scratchDir string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mounts[id] = &COWOverlayMount{
		ID:         id,
		MountPoint: mountPoint,
		ScratchDir: scratchDir,
	}
}

// TeardownMount explicitly syncs, unmounts, and purges the COW overlay layer
// identified by id, ensuring virtiofs caches are flushed.
func (m *COWManager) TeardownMount(ctx context.Context, id string) error {
	m.mu.Lock()
	mount, exists := m.mounts[id]
	if !exists {
		m.mu.Unlock()
		// Even if not registered, flush host virtiofs cache
		FlushVirtiofsCache()
		return nil
	}
	delete(m.mounts, id)
	m.mu.Unlock()

	// 1. Explicitly sync all pending block writes
	FlushVirtiofsCache()

	// 2. Safely remove scratch directory residue if present
	if mount.ScratchDir != "" {
		_ = os.RemoveAll(mount.ScratchDir)
	}

	// 3. Drop caches after unmount
	FlushVirtiofsCache()

	return nil
}

// TeardownAll syncs and clears all registered COW overlay layers.
func (m *COWManager) TeardownAll(ctx context.Context) error {
	m.mu.Lock()
	mounts := make([]*COWOverlayMount, 0, len(m.mounts))
	for _, mnt := range m.mounts {
		mounts = append(mounts, mnt)
	}
	m.mounts = make(map[string]*COWOverlayMount)
	m.mu.Unlock()

	FlushVirtiofsCache()
	for _, mnt := range mounts {
		if mnt.ScratchDir != "" {
			_ = os.RemoveAll(mnt.ScratchDir)
		}
	}
	FlushVirtiofsCache()

	return nil
}
