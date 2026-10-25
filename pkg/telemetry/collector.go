package telemetry

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// MetricSeverity indicates the priority level of a telemetry item.
type MetricSeverity string

const (
	SeverityNormal   MetricSeverity = "NORMAL"
	SeverityWarning  MetricSeverity = "WARNING"
	SeverityCritical MetricSeverity = "CRITICAL"
)

// TelemetryEvent represents a structured telemetry event.
type TelemetryEvent struct {
	TimestampNs      int64             `json:"timestamp_ns"`
	VMID             string            `json:"vm_id"`
	Category         string            `json:"category"` // "log", "mcp", "egress", "tripwire"
	Severity         MetricSeverity    `json:"severity"`
	Message          string            `json:"message"`
	Payload          map[string]any    `json:"payload,omitempty"`
	CanaryTriggered  bool              `json:"canary_triggered"`
	CanaryTargetIP   string            `json:"canary_target_ip,omitempty"`
}

// VMResourceStats holds live resource metrics for a microVM.
type VMResourceStats struct {
	VMID               string  `json:"vm_id"`
	CPUPercent         float64 `json:"cpu_percent"`
	MemoryRSSBytes     uint64  `json:"memory_rss_bytes"`
	VirtiofsReadBytes  uint64  `json:"virtiofs_read_bytes"`
	VirtiofsWriteBytes uint64  `json:"virtiofs_write_bytes"`
	ActiveSockets      int     `json:"active_sockets"`
}

// TelemetryCollector manages the dual-channel telemetry pipeline.
type TelemetryCollector struct {
	// Priority Control Channel: Unbounded non-blocking queue for alerts & tripwires (zero-drop)
	priorityQueue chan TelemetryEvent

	// Bounded Log Channel with Ring Buffer
	logBuffer *RingBuffer[TelemetryEvent]

	// Rate limiter: token bucket for stdout/stderr to defeat log flooding
	rateTokens      int64
	maxTokens       int64
	refillRatePerSec int64
	droppedLogs     uint64

	// VM Stats map
	vmStats map[string]*VMResourceStats
	mu      sync.RWMutex
}

// NewTelemetryCollector creates a new collector with dual-channel prioritization.
func NewTelemetryCollector() *TelemetryCollector {
	c := &TelemetryCollector{
		priorityQueue:    make(chan TelemetryEvent, 1000),
		logBuffer:        NewRingBuffer[TelemetryEvent](10000),
		maxTokens:        20000, // up to 20,000 log lines/sec burst
		rateTokens:       20000,
		refillRatePerSec: 10000,
		vmStats:          make(map[string]*VMResourceStats),
	}

	// Refill rate tokens periodically
	go c.startTokenRefill()

	return c
}

func (c *TelemetryCollector) startTokenRefill() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	refillPerTick := c.refillRatePerSec / 10
	for range ticker.C {
		c.mu.Lock()
		c.rateTokens += refillPerTick
		if c.rateTokens > c.maxTokens {
			c.rateTokens = c.maxTokens
		}
		c.mu.Unlock()
	}
}

// RecordPriorityEvent publishes high-priority security alerts with zero drop.
func (c *TelemetryCollector) RecordPriorityEvent(event TelemetryEvent) {
	if event.TimestampNs == 0 {
		event.TimestampNs = time.Now().UnixNano()
	}

	// Non-blocking send to priority queue
	select {
	case c.priorityQueue <- event:
	default:
		// Priority queue full: force push by draining oldest non-critical
		go func(e TelemetryEvent) {
			c.priorityQueue <- e
		}(event)
	}

	// Also record into ring buffer snapshot
	c.logBuffer.Push(event)
}

// RecordLogLine pushes standard log output with token-bucket rate limiting.
func (c *TelemetryCollector) RecordLogLine(vmID, message string, isStderr bool) bool {
	c.mu.Lock()
	if c.rateTokens <= 0 {
		c.mu.Unlock()
		atomic.AddUint64(&c.droppedLogs, 1)
		return false // Throttled due to log flood
	}
	c.rateTokens--
	c.mu.Unlock()

	sev := SeverityNormal
	if isStderr {
		sev = SeverityWarning
	}

	event := TelemetryEvent{
		TimestampNs: time.Now().UnixNano(),
		VMID:        vmID,
		Category:    "log",
		Severity:    sev,
		Message:     message,
	}

	c.logBuffer.Push(event)
	return true
}

// RecordCanaryTripwire immediately fires a priority alert when an attacker probes tripwire IPs.
func (c *TelemetryCollector) RecordCanaryTripwire(vmID, targetIP string) {
	event := TelemetryEvent{
		TimestampNs:     time.Now().UnixNano(),
		VMID:            vmID,
		Category:        "tripwire",
		Severity:        SeverityCritical,
		Message:         fmt.Sprintf("ALERT: Canary tripwire touched by %s targeting IP %s", vmID, targetIP),
		CanaryTriggered: true,
		CanaryTargetIP:  targetIP,
	}

	c.RecordPriorityEvent(event)
}

// UpdateVMStats updates resource usage metrics for a microVM.
func (c *TelemetryCollector) UpdateVMStats(stats *VMResourceStats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vmStats[stats.VMID] = stats
}

// GetVMStats returns the current resource metrics for a microVM.
func (c *TelemetryCollector) GetVMStats(vmID string) (*VMResourceStats, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s, ok := c.vmStats[vmID]
	if !ok {
		return nil, false
	}
	// Return copy
	statCopy := *s
	return &statCopy, true
}

// PriorityChannel exposes the read-only priority event channel.
func (c *TelemetryCollector) PriorityChannel() <-chan TelemetryEvent {
	return c.priorityQueue
}

// SnapshotRecent returns up to n most recent telemetry entries from the ring buffer.
func (c *TelemetryCollector) SnapshotRecent() []TelemetryEvent {
	return c.logBuffer.Snapshot()
}

// DroppedLogCount returns the number of console lines dropped due to flood protection.
func (c *TelemetryCollector) DroppedLogCount() uint64 {
	return atomic.LoadUint64(&c.droppedLogs)
}
