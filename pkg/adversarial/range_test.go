package adversarial

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRange_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg := RangeConfig{
		Scenario:            "artex-machine-speed",
		Strict:              true,
		SprayRatePerMin:     2900,
		VelocityThresholdMs: 500 * time.Millisecond,
	}

	engine := NewRangeEngine(cfg)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("RangeEngine.Run failed: %v", err)
	}

	if !report.Passed {
		t.Fatalf("expected adversarial range run to pass, but failed: %+v", report)
	}

	if len(report.Invariants) != 3 {
		t.Fatalf("expected 3 invariants evaluated, got %d", len(report.Invariants))
	}

	for _, inv := range report.Invariants {
		if !inv.Passed {
			t.Errorf("Invariant %d (%s) failed: %s", inv.Index, inv.Name, inv.Summary)
		}
	}

	if !report.MicroVMTornDown {
		t.Errorf("expected microVM to be cleanly torn down")
	}

	summary := report.FormatSummary()
	if !strings.Contains(summary, "[PASS] Invariant 1: Cross-Tenant Isolation (Attempts blocked: 100%)") {
		t.Errorf("summary missing invariant 1 pass tag: %s", summary)
	}
	if !strings.Contains(summary, "[PASS] Invariant 2: Velocity Killswitch Tripped in") {
		t.Errorf("summary missing invariant 2 pass tag: %s", summary)
	}
	if !strings.Contains(summary, "[PASS] Invariant 3: Host Credential Bleed (Harvested: 0 bytes)") {
		t.Errorf("summary missing invariant 3 pass tag: %s", summary)
	}
	if !strings.Contains(summary, "Total Run Time:") || !strings.Contains(summary, "(MicroVM teardown complete)") {
		t.Errorf("summary missing total run time or teardown line: %s", summary)
	}
}

func TestRange_Invariant1_CrossTenant(t *testing.T) {
	ctx := context.Background()
	synthNet := NewSyntheticNetwork(SyntheticNetworkConfig{
		AllowedTenantID: "tenant-alpha-001",
	})
	defer synthNet.Close()

	inv := RunInvariant1_CrossTenant(ctx, synthNet)
	if !inv.Passed {
		t.Fatalf("expected Invariant 1 to pass, got: %s", inv.Summary)
	}

	att, blk, pct := synthNet.CrossTenantStats()
	if att == 0 || blk != att || pct != 100.0 {
		t.Errorf("expected 100%% cross-tenant blocked, got att=%d, blk=%d, pct=%.2f", att, blk, pct)
	}
}

func TestRange_Invariant2_VelocityKillswitch(t *testing.T) {
	ctx := context.Background()
	synthNet := NewSyntheticNetwork(SyntheticNetworkConfig{
		AllowedTenantID:     "tenant-alpha-001",
		SprayVelocityBurst:  15,
		SprayWindowDuration: 500 * time.Millisecond,
	})
	defer synthNet.Close()

	inv := RunInvariant2_VelocityKillswitch(ctx, synthNet, 2900, 500*time.Millisecond)
	if !inv.Passed {
		t.Fatalf("expected Invariant 2 to pass, got: %s", inv.Summary)
	}

	if !synthNet.CircuitTripped() {
		t.Errorf("expected circuit breaker to be tripped")
	}
	if !synthNet.TokenRevoked() {
		t.Errorf("expected active token to be revoked")
	}

	latency := synthNet.TripLatency()
	if latency <= 0 || latency > 500*time.Millisecond {
		t.Errorf("expected trip latency to be < 500ms, got: %s", latency)
	}
}

func TestRange_Invariant3_HostCredentialBleed(t *testing.T) {
	ctx := context.Background()
	harness, err := NewSandboxHarness(ctx, HarnessConfig{
		SessionID: "test-bleed",
		Airgap:    true,
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}
	defer harness.Teardown(ctx)

	inv := RunInvariant3_HostCredentialBleed(ctx, harness)
	if !inv.Passed {
		t.Fatalf("expected Invariant 3 to pass, got: %s", inv.Summary)
	}

	harvested, ok := inv.Metrics["harvested_bytes"].(int)
	if !ok || harvested != 0 {
		t.Errorf("expected 0 harvested bytes, got %d", harvested)
	}
}

func TestRange_SyntheticNetwork_AirgapAndCanary(t *testing.T) {
	ctx := context.Background()
	synthNet := NewSyntheticNetwork(SyntheticNetworkConfig{})
	defer synthNet.Close()

	// Verify WAN dial attempts are rejected under airgap
	err := synthNet.VerifyZeroWANEgress(ctx)
	if err != nil {
		t.Errorf("VerifyZeroWANEgress failed: %v", err)
	}

	// Verify canary endpoint
	resp, err := http.Get(synthNet.BaseURL() + "/canary/tripwire")
	if err != nil {
		t.Fatalf("failed to call canary endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("expected 502 Bad Gateway on canary endpoint, got %d", resp.StatusCode)
	}
}

func TestRange_StrictModeFailure(t *testing.T) {
	report := &RangeReport{
		Scenario: "artex-machine-speed",
		Passed:   false,
		Invariants: []InvariantResult{
			{
				Index:   1,
				Name:    "Cross-Tenant Isolation",
				Passed:  false,
				Summary: "Attempts blocked: 80% (10/50 bypassed)",
			},
		},
	}

	summary := report.FormatSummary()
	if !strings.Contains(summary, "[FAIL] Invariant 1") {
		t.Errorf("expected [FAIL] tag for failing invariant: %s", summary)
	}
}

func TestRange_ToJSON(t *testing.T) {
	report := &RangeReport{
		Scenario:      "artex-machine-speed",
		Passed:        true,
		TotalDuration: 3200 * time.Millisecond,
		Invariants: []InvariantResult{
			{Index: 1, Name: "Cross-Tenant Isolation", Passed: true, Summary: "Attempts blocked: 100%"},
			{Index: 2, Name: "Velocity Killswitch", Passed: true, Summary: "Velocity Killswitch Tripped in 280ms"},
			{Index: 3, Name: "Host Credential Bleed", Passed: true, Summary: "Harvested: 0 bytes"},
		},
	}

	data, err := report.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize report to JSON: %v", err)
	}

	var parsed RangeReport
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON generated: %v", err)
	}

	if parsed.Scenario != report.Scenario || !parsed.Passed || len(parsed.Invariants) != 3 {
		t.Errorf("JSON parse mismatch: %+v", parsed)
	}
}
