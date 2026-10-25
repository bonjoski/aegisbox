package telemetry

import (
	"sync"
	"sync/atomic"
)

// RingBuffer is a thread-safe, non-blocking fixed-capacity ring buffer for high-throughput telemetry.
// Oldest items are overwritten when capacity is reached.
type RingBuffer[T any] struct {
	capacity uint64
	mask     uint64
	entries  []T
	writeIdx uint64
	count    uint64
	mu       sync.RWMutex
}

// NewRingBuffer initializes a ring buffer with the given capacity rounded up to power of 2.
func NewRingBuffer[T any](capacity int) *RingBuffer[T] {
	if capacity <= 0 {
		capacity = 1024
	}

	// Round up to power of 2 for fast bitwise masking
	powerOfTwo := uint64(1)
	for powerOfTwo < uint64(capacity) {
		powerOfTwo <<= 1
	}

	return &RingBuffer[T]{
		capacity: powerOfTwo,
		mask:     powerOfTwo - 1,
		entries:  make([]T, powerOfTwo),
	}
}

// Push adds an item to the ring buffer, overwriting the oldest entry if full.
func (r *RingBuffer[T]) Push(item T) {
	r.mu.Lock()
	idx := atomic.AddUint64(&r.writeIdx, 1) - 1
	r.entries[idx&r.mask] = item
	if r.count < r.capacity {
		r.count++
	}
	r.mu.Unlock()
}

// Snapshot returns a copy of all current items ordered from oldest to newest.
func (r *RingBuffer[T]) Snapshot() []T {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.count == 0 {
		return nil
	}

	result := make([]T, r.count)
	startIdx := r.writeIdx - r.count
	for i := uint64(0); i < r.count; i++ {
		result[i] = r.entries[(startIdx+i)&r.mask]
	}

	return result
}

// Len returns the current number of items in the buffer.
func (r *RingBuffer[T]) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return int(r.count)
}

// Clear flushes all entries in the ring buffer.
func (r *RingBuffer[T]) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.writeIdx = 0
	r.count = 0
	r.entries = make([]T, r.capacity)
}
