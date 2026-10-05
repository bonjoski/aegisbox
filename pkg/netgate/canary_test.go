package netgate_test

import (
	"sync"
	"testing"

	"github.com/bonjoski/ironbox/pkg/netgate"
)

func TestCanaryMonitor_TripwireHit(t *testing.T) {
	monitor := netgate.NewCanaryMonitor()
	defer monitor.Close()

	var mu sync.Mutex
	triggered := false
	var triggeredIP string

	monitor.RegisterVM("vm-test-42", netgate.CanaryConfig{
		TrapIPs: []string{"10.99.99.99", "169.254.169.254"},
		OnTrapTrigger: func(vmID, trapIP string) {
			mu.Lock()
			triggered = true
			triggeredIP = trapIP
			mu.Unlock()
		},
	})

	// 1. Send permitted probe
	hit := monitor.RecordProbe("vm-test-42", "10.200.5.42")
	if hit {
		t.Errorf("expected non-canary probe to return false")
	}

	// 2. Send canary probe
	hitCanary := monitor.RecordProbe("vm-test-42", "169.254.169.254")
	if !hitCanary {
		t.Errorf("expected canary probe to return true")
	}

	select {
	case event := <-monitor.Events():
		if event == "" {
			t.Errorf("expected non-empty alert event")
		}
	default:
		t.Errorf("expected event in monitor.Events()")
	}

	mu.Lock()
	if !triggered || triggeredIP != "169.254.169.254" {
		t.Errorf("expected callback trigger with 169.254.169.254, got triggered=%v ip=%s", triggered, triggeredIP)
	}
	mu.Unlock()
}

