package netgate

import (
	"context"
	"fmt"
	"net"
	"sync"
)

// TargetRule specifies the permitted destination host and ports for scoped adversarial testing.
type TargetRule struct {
	Host     string   `json:"host"`
	Ports    []int    `json:"ports"`
	Protocol string   `json:"protocol"` // "tcp", "udp", or "all"
}

// CanaryConfig configures canary tripwire IPs that trigger instantaneous VM termination.
type CanaryConfig struct {
	TrapIPs       []string                  `json:"trap_ips"`
	OnTrapTrigger func(vmID, trapIP string) `json:"-"`
}

// NetworkGovernor manages host-level packet filter pinning and canary monitors.
type NetworkGovernor interface {
	Name() string
	ApplyPinning(ctx context.Context, vmID string, target TargetRule, canary CanaryConfig) error
	RevokePinning(ctx context.Context, vmID string) error
	CanaryAlertChan() <-chan string
}

// NewPlatformGovernor returns the host OS platform-specific network governor.
func NewPlatformGovernor() NetworkGovernor {
	return newPlatformGovernor()
}


// MemoryGovernor provides an in-memory/simulated network governor for testing and dry-run modes.
type MemoryGovernor struct {
	mu        sync.Mutex
	pinned    map[string]TargetRule
	canaryIPs map[string][]string
	alerts    chan string
}

// NewMemoryGovernor returns a new MemoryGovernor.
func NewMemoryGovernor() *MemoryGovernor {
	return &MemoryGovernor{
		pinned:    make(map[string]TargetRule),
		canaryIPs: make(map[string][]string),
		alerts:    make(chan string, 10),
	}
}

func (m *MemoryGovernor) Name() string {
	return "memory-governor"
}

func (m *MemoryGovernor) ApplyPinning(ctx context.Context, vmID string, target TargetRule, canary CanaryConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if target.Host != "" {
		if net.ParseIP(target.Host) == nil {
			// Resolve hostname to test validation
			if _, err := net.LookupIP(target.Host); err != nil {
				return fmt.Errorf("invalid target host %q: %w", target.Host, err)
			}
		}
	}

	m.pinned[vmID] = target
	m.canaryIPs[vmID] = canary.TrapIPs
	return nil
}

func (m *MemoryGovernor) RevokePinning(ctx context.Context, vmID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.pinned, vmID)
	delete(m.canaryIPs, vmID)
	return nil
}

func (m *MemoryGovernor) CanaryAlertChan() <-chan string {
	return m.alerts
}

// TriggerCanaryTest simulates a canary tripwire violation.
func (m *MemoryGovernor) TriggerCanaryTest(vmID, trapIP string) {
	select {
	case m.alerts <- fmt.Sprintf("TRIPWIRE_TRIGGERED: vm=%s trap_ip=%s", vmID, trapIP):
	default:
	}
}
