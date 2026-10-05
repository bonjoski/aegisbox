package netgate_test

import (
	"context"
	"testing"

	"github.com/bonjoski/ironbox/pkg/netgate"
)

func TestMemoryGovernor_PinningAndCanary(t *testing.T) {
	ctx := context.Background()
	gov := netgate.NewMemoryGovernor()

	rule := netgate.TargetRule{
		Host:     "127.0.0.1",
		Ports:    []int{80, 443},
		Protocol: "tcp",
	}

	canary := netgate.CanaryConfig{
		TrapIPs: []string{"10.99.99.99", "169.254.169.254"},
	}

	err := gov.ApplyPinning(ctx, "vm-test-1", rule, canary)
	if err != nil {
		t.Fatalf("failed to apply pinning: %v", err)
	}

	// Trigger canary tripwire simulation
	gov.TriggerCanaryTest("vm-test-1", "169.254.169.254")

	select {
	case alert := <-gov.CanaryAlertChan():
		if alert == "" {
			t.Errorf("expected non-empty canary alert")
		}
	default:
		t.Errorf("expected canary alert to be emitted")
	}

	if err := gov.RevokePinning(ctx, "vm-test-1"); err != nil {
		t.Fatalf("failed to revoke pinning: %v", err)
	}
}
