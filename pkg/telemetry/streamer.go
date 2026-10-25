package telemetry

import (
	"context"
	"sync"
	"time"
)

// StreamSubscriber receives streaming telemetry updates.
type StreamSubscriber chan TelemetryEvent

// TelemetryStreamer broadcasts telemetry events to multiple concurrent subscribers.
type TelemetryStreamer struct {
	collector   *TelemetryCollector
	subscribers map[StreamSubscriber]struct{}
	mu          sync.RWMutex
}

// NewTelemetryStreamer creates a streamer wrapping the collector.
func NewTelemetryStreamer(collector *TelemetryCollector) *TelemetryStreamer {
	s := &TelemetryStreamer{
		collector:   collector,
		subscribers: make(map[StreamSubscriber]struct{}),
	}

	// Forward priority channel events to all subscribers
	go s.forwardPriorityLoop()

	return s
}

func (s *TelemetryStreamer) forwardPriorityLoop() {
	for event := range s.collector.PriorityChannel() {
		s.Broadcast(event)
	}
}

// Subscribe registers a new subscriber channel.
func (s *TelemetryStreamer) Subscribe(bufferSize int) StreamSubscriber {
	if bufferSize <= 0 {
		bufferSize = 256
	}

	ch := make(StreamSubscriber, bufferSize)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	s.mu.Unlock()

	return ch
}

// Unsubscribe removes a subscriber channel.
func (s *TelemetryStreamer) Unsubscribe(ch StreamSubscriber) {
	s.mu.Lock()
	if _, ok := s.subscribers[ch]; ok {
		delete(s.subscribers, ch)
		close(ch)
	}
	s.mu.Unlock()
}

// Broadcast distributes an event to all subscribers without blocking.
func (s *TelemetryStreamer) Broadcast(event TelemetryEvent) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for ch := range s.subscribers {
		select {
		case ch <- event:
		default:
			// Non-blocking drop for slow consumers to prevent lag
		}
	}
}

// StreamPeriodicMetrics runs a periodic ticker emitting VM resource metrics to subscribers.
func (s *TelemetryStreamer) StreamPeriodicMetrics(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Collect snapshots and broadcast
			events := s.collector.SnapshotRecent()
			if len(events) > 0 {
				latest := events[len(events)-1]
				s.Broadcast(latest)
			}
		}
	}
}
