package adversarial_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/aegisbox/pkg/adversarial"
)

// TestArtexAdversarialRange_EndToEnd executes the ARTEX-grade machine-speed adversarial testbed
// against an ephemeral microVM harness with air-gapped synthetic virtual networking.
func TestArtexAdversarialRange_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := adversarial.RangeConfig{
		Scenario:            "artex-machine-speed",
		Strict:              true,
		SprayRatePerMin:     2900,
		VelocityThresholdMs: 500 * time.Millisecond,
	}

	engine := adversarial.NewRangeEngine(cfg)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("Adversarial Range execution failed: %v", err)
	}

	if !report.Passed {
		t.Fatalf("Adversarial Range failed: %+v", report)
	}

	// Verify microVM was torn down cleanly
	if !report.MicroVMTornDown {
		t.Errorf("MicroVM was not torn down after range completion")
	}

	// Verify air-gap verification
	if !report.AirgapVerified {
		t.Errorf("Synthetic network failed air-gap verification")
	}

	// Verify all 3 invariants passed
	if len(report.Invariants) != 3 {
		t.Fatalf("expected 3 core security invariants, got %d", len(report.Invariants))
	}

	// Invariant 1: Cross-Tenant Isolation
	inv1 := report.Invariants[0]
	if !inv1.Passed {
		t.Errorf("Invariant 1 (Cross-Tenant Isolation) failed: %s", inv1.Summary)
	}
	if !strings.Contains(inv1.Summary, "100%") {
		t.Errorf("Invariant 1 did not block 100%% of attempts: %s", inv1.Summary)
	}

	// Invariant 2: Velocity Killswitch
	inv2 := report.Invariants[1]
	if !inv2.Passed {
		t.Errorf("Invariant 2 (Velocity Killswitch) failed: %s", inv2.Summary)
	}
	tripMs, ok := inv2.Metrics["trip_latency_ms"].(int64)
	if !ok || tripMs > 500 {
		t.Errorf("Invariant 2 trip latency exceeded 500ms limit: %v", tripMs)
	}

	// Invariant 3: Host Credential Bleed
	inv3 := report.Invariants[2]
	if !inv3.Passed {
		t.Errorf("Invariant 3 (Host Credential Bleed) failed: %s", inv3.Summary)
	}
	harvestedBytes, ok := inv3.Metrics["harvested_bytes"].(int)
	if !ok || harvestedBytes != 0 {
		t.Errorf("CRITICAL SECURITY DEFECT: Invariant 3 harvested %d bytes of host secrets", harvestedBytes)
	}

	// Verify formatted output matches RFC specification
	formatted := report.FormatSummary()
	if !strings.Contains(formatted, "[PASS] Invariant 1: Cross-Tenant Isolation (Attempts blocked: 100%)") {
		t.Errorf("summary missing invariant 1 PASS tag:\n%s", formatted)
	}
	if !strings.Contains(formatted, "[PASS] Invariant 2: Velocity Killswitch Tripped in") {
		t.Errorf("summary missing invariant 2 PASS tag:\n%s", formatted)
	}
	if !strings.Contains(formatted, "[PASS] Invariant 3: Host Credential Bleed (Harvested: 0 bytes)") {
		t.Errorf("summary missing invariant 3 PASS tag:\n%s", formatted)
	}
	if !strings.Contains(formatted, "Total Run Time:") || !strings.Contains(formatted, "(MicroVM teardown complete)") {
		t.Errorf("summary missing total run time or teardown line:\n%s", formatted)
	}
}

// TestArtexAdversarialRange_CrossTenantIsolationDeepDive validates Conjoiner IAM scope attenuation.
func TestArtexAdversarialRange_CrossTenantIsolationDeepDive(t *testing.T) {
	ctx := context.Background()

	net := adversarial.NewSyntheticNetwork(adversarial.SyntheticNetworkConfig{
		AllowedTenantID: "tenant-alpha-001",
	})
	defer net.Close()

	inv := adversarial.RunInvariant1_CrossTenant(ctx, net)
	if !inv.Passed {
		t.Fatalf("Cross-tenant isolation evaluation failed: %s", inv.Summary)
	}

	attempts, blocked, pct := net.CrossTenantStats()
	if attempts < 50 {
		t.Errorf("expected at least 50 cross-tenant attempts, got %d", attempts)
	}
	if blocked != attempts {
		t.Errorf("expected all %d attempts to be blocked, but %d were blocked", attempts, blocked)
	}
	if pct != 100.0 {
		t.Errorf("expected 100.0%% blocked, got %.2f%%", pct)
	}
}

// TestArtexAdversarialRange_VelocityKillswitchSprayRates tests various spray rates.
func TestArtexAdversarialRange_VelocityKillswitchSprayRates(t *testing.T) {
	ctx := context.Background()

	net := adversarial.NewSyntheticNetwork(adversarial.SyntheticNetworkConfig{
		AllowedTenantID:     "tenant-alpha-001",
		SprayVelocityBurst:  20,
		SprayWindowDuration: 500 * time.Millisecond,
	})
	defer net.Close()

	inv := adversarial.RunInvariant2_VelocityKillswitch(ctx, net, 2900, 500*time.Millisecond)
	if !inv.Passed {
		t.Fatalf("Velocity killswitch failed at 2,900 req/min: %s", inv.Summary)
	}

	if !net.CircuitTripped() {
		t.Errorf("Circuit breaker failed to trip")
	}
	if !net.TokenRevoked() {
		t.Errorf("Active DPoP token was not revoked")
	}

	latency := net.TripLatency()
	if latency <= 0 || latency >= 500*time.Millisecond {
		t.Errorf("Trip latency out of bounds: %v (expected > 0 and < 500ms)", latency)
	}
}

// TestArtexAdversarialRange_ZeroHostCredentialBleed confirms filesystem containment.
func TestArtexAdversarialRange_ZeroHostCredentialBleed(t *testing.T) {
	ctx := context.Background()

	harness, err := adversarial.NewSandboxHarness(ctx, adversarial.HarnessConfig{
		SessionID: "bleed-test-harness",
		Airgap:    true,
	})
	if err != nil {
		t.Fatalf("failed to create sandbox harness: %v", err)
	}
	defer harness.Teardown(ctx)

	inv := adversarial.RunInvariant3_HostCredentialBleed(ctx, harness)
	if !inv.Passed {
		t.Fatalf("Host credential bleed test failed: %s", inv.Summary)
	}

	harvestedBytes := inv.Metrics["harvested_bytes"].(int)
	if harvestedBytes != 0 {
		t.Fatalf("CRITICAL: Host secrets leaked: %d bytes harvested", harvestedBytes)
	}
}

// TestArtexAdversarialRange_AirgapWANNetworkLeakage ensures no outbound packets escape to WAN.
func TestArtexAdversarialRange_AirgapWANNetworkLeakage(t *testing.T) {
	ctx := context.Background()

	harness, err := adversarial.NewSandboxHarness(ctx, adversarial.HarnessConfig{
		SessionID: "wan-leakage-test",
		Airgap:    true,
	})
	if err != nil {
		t.Fatalf("failed to create sandbox harness: %v", err)
	}
	defer harness.Teardown(ctx)

	if err := harness.VerifyZeroWANEgress(ctx); err != nil {
		t.Fatalf("Airgap WAN leakage detected: %v", err)
	}
}
