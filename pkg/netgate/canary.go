package netgate

import (
	"fmt"
	"sync"
	"time"
)


// CanaryMonitor watches for egress attempts towards forbidden tripwire destinations.
type CanaryMonitor struct {
	mu        sync.Mutex
	activeVMs map[string]CanaryConfig
	events    chan string
	stopChan  chan struct{}
}

// NewCanaryMonitor creates a new CanaryMonitor.
func NewCanaryMonitor() *CanaryMonitor {
	return &CanaryMonitor{
		activeVMs: make(map[string]CanaryConfig),
		events:    make(chan string, 100),
		stopChan:  make(chan struct{}),
	}
}

// RegisterVM associates canary tripwires with an active VM.
func (m *CanaryMonitor) RegisterVM(vmID string, cfg CanaryConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeVMs[vmID] = cfg
}

// UnregisterVM removes canary tracking for a terminated VM.
func (m *CanaryMonitor) UnregisterVM(vmID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.activeVMs, vmID)
}

// RecordProbe records an egress packet attempt and triggers instant kill if it matches a canary IP.
func (m *CanaryMonitor) RecordProbe(vmID, destIP string) bool {
	m.mu.Lock()
	cfg, exists := m.activeVMs[vmID]
	m.mu.Unlock()

	if !exists {
		return false
	}

	for _, trap := range cfg.TrapIPs {
		if trap == destIP {
			alertMsg := fmt.Sprintf("🚨 CANARY TRIPWIRE HIT: VM [%s] attempted egress to prohibited trap IP %s at %s", vmID, destIP, time.Now().Format(time.RFC3339))
			select {
			case m.events <- alertMsg:
			default:
			}

			if cfg.OnTrapTrigger != nil {
				cfg.OnTrapTrigger(vmID, destIP)
			}
			return true

		}
	}

	return false
}

// Events returns the alert event stream channel.
func (m *CanaryMonitor) Events() <-chan string {
	return m.events
}

// Close terminates the canary monitor.
func (m *CanaryMonitor) Close() {
	select {
	case <-m.stopChan:
		return
	default:
		close(m.stopChan)
	}
}
