package benchmark

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFabrialSuite_CatalogCompleteness(t *testing.T) {
	catalog := DefaultFabrialCatalog()
	if len(catalog) != 16 {
		t.Fatalf("expected 16 default Fabrial benchmark vectors, got %d", len(catalog))
	}

	pillarCounts := make(map[FabrialPillar]int)
	for _, v := range catalog {
		if v.ID == "" || v.Name == "" || v.Payload == "" {
			t.Fatalf("invalid vector found with empty fields: %+v", v)
		}
		pillarCounts[v.Pillar]++
	}

	expectedPillars := []FabrialPillar{
		PillarSecretExfiltration,
		PillarScopeEscalation,
		PillarKernelEvasion,
		PillarPromptInjection,
	}

	for _, p := range expectedPillars {
		if pillarCounts[p] < 4 {
			t.Fatalf("expected at least 4 vectors for pillar %s, got %d", p, pillarCounts[p])
		}
	}
}

func TestFabrialSuite_ExecutionAndDefenseRate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runner := NewFabrialSuiteRunner(4, true)
	report, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("failed executing Fabrial comparative suite: %v", err)
	}

	if !report.Passed {
		t.Fatalf("expected Fabrial suite to pass with 100%% defense rate")
	}
	if report.DefendedVectors != 16 {
		t.Fatalf("expected 16 defended vectors, got %d", report.DefendedVectors)
	}
	if report.FabrialDefendedPct != 100.0 {
		t.Fatalf("expected Fabrial defense percentage to be 100.0, got %f", report.FabrialDefendedPct)
	}
	if report.ControlVulnerablePct != 100.0 {
		t.Fatalf("expected Control vulnerability percentage to be 100.0, got %f", report.ControlVulnerablePct)
	}
}

func TestFabrialSuite_ScorecardAndJSONOutput(t *testing.T) {
	ctx := context.Background()
	runner := NewFabrialSuiteRunner(4, true)
	report, err := runner.Run(ctx)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	// 1. Test Scorecard output
	scorecard := report.FormatScorecard()
	if !strings.Contains(scorecard, "AEGISBOX CROSS-FABRIAL ADVERSARIAL VALIDATION REPORT") {
		t.Fatalf("scorecard missing header: %s", scorecard)
	}
	if !strings.Contains(scorecard, "ZERO SECRET LEAKAGE") {
		t.Fatalf("scorecard missing final verdict: %s", scorecard)
	}
	if !strings.Contains(scorecard, "[PASS]") {
		t.Fatalf("scorecard missing PASS status: %s", scorecard)
	}

	// 2. Test JSON serialization
	jsonData, err := report.ToJSON()
	if err != nil {
		t.Fatalf("failed serializing report to JSON: %v", err)
	}

	var parsed FabrialBenchmarkReport
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("failed unmarshaling serialized JSON: %v", err)
	}
	if parsed.TotalVectors != 16 || !parsed.Passed {
		t.Fatalf("unmarshaled JSON mismatch: total=%d, passed=%v", parsed.TotalVectors, parsed.Passed)
	}
}
