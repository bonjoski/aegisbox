package aisafety

import (
	"context"
	"sync/atomic"
)

const DefaultMaxConcurrentSlots = 4

// SlotSemaphore enforces a hard concurrency ceiling (default 4 active slots across N=8 callers)
// to prevent host RAM thrashing, port collisions, or microVM exhaustion.
type SlotSemaphore struct {
	sem    chan struct{}
	max    int
	active atomic.Int64
	peak   atomic.Int64
}

// NewSlotSemaphore creates a bounded concurrency semaphore capped at maxSlots.
func NewSlotSemaphore(maxSlots int) *SlotSemaphore {
	if maxSlots <= 0 {
		maxSlots = DefaultMaxConcurrentSlots
	}
	return &SlotSemaphore{
		sem: make(chan struct{}, maxSlots),
		max: maxSlots,
	}
}

// Acquire blocks until a slot is available or ctx is cancelled.
func (s *SlotSemaphore) Acquire(ctx context.Context) error {
	select {
	case s.sem <- struct{}{}:
		cur := s.active.Add(1)
		for {
			prev := s.peak.Load()
			if cur <= prev || s.peak.CompareAndSwap(prev, cur) {
				break
			}
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees one acquired concurrency slot.
// Decrements active BEFORE freeing the channel token so waiting Acquire callers
// never observe active > max due to scheduler interleaving.
func (s *SlotSemaphore) Release() {
	for {
		cur := s.active.Load()
		if cur <= 0 {
			return
		}
		if s.active.CompareAndSwap(cur, cur-1) {
			break
		}
	}
	select {
	case <-s.sem:
	default:
	}
}

// MaxSlots returns the configured maximum number of concurrent slots.
func (s *SlotSemaphore) MaxSlots() int {
	return s.max
}

// Active returns the current number of active slots.
func (s *SlotSemaphore) Active() int64 {
	return s.active.Load()
}

// Peak returns the highest number of simultaneously active slots observed.
func (s *SlotSemaphore) Peak() int64 {
	return s.peak.Load()
}

// ResetPeak resets peak tracking (useful in tests).
func (s *SlotSemaphore) ResetPeak() {
	s.peak.Store(s.active.Load())
}
