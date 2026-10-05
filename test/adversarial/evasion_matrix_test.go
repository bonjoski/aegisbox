package adversarial_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/aegisbox/pkg/argus"
	"github.com/bonjoski/aegisbox/pkg/benchmark"
)

// TestEvasionMatrix_FullBenchmarkZeroEvasion ensures 100% detection and neutralization across all known attack vectors.
func TestEvasionMatrix_FullBenchmarkZeroEvasion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	engine := benchmark.NewEngine()
	report, err := engine.Run(ctx, benchmark.EngineConfig{
		Concurrency: 4,
		Strict:      true,
	})
	if err != nil {
		t.Fatalf("benchmark engine run failed: %v", err)
	}

	if report.TotalVectors < 15 {
		t.Errorf("expected at least 15 adversarial test vectors, got %d", report.TotalVectors)
	}

	if report.AllowedCount != 0 {
		t.Errorf("CRITICAL SECURITY DEFECT: %d adversarial vector(s) bypassed defenses!", report.AllowedCount)
	}

	if report.DetectionRate != 100.0 {
		t.Errorf("expected 100.0%% detection rate, got %.2f%%", report.DetectionRate)
	}

	if !report.Passed {
		t.Errorf("expected benchmark suite to pass in strict mode, but passed was false")
	}

	for _, res := range report.Results {
		if !res.Defended || res.Status != "BLOCKED" {
			t.Errorf("ADVERSARIAL EVASION: Vector %s (%s) was not blocked! Status: %s, Details: %s",
				res.ID, res.Name, res.Status, res.Details)
		}
		if res.DetectedSeverity == "" || res.DetectedSeverity == "NONE" {
			t.Errorf("Vector %s missing detected severity", res.ID)
		}
		if res.MitreID == "" {
			t.Errorf("Vector %s missing MITRE ATT&CK ID", res.ID)
		}
		if res.DetectionGate != "PreFlight" && res.DetectionGate != "Sandbox" {
			t.Errorf("Vector %s reported unexpected detection gate: %s", res.ID, res.DetectionGate)
		}
	}
}

// TestEvasionMatrix_AllCategoriesRepresented verifies coverage and defense across all 9 attack categories.
func TestEvasionMatrix_AllCategoriesRepresented(t *testing.T) {
	ctx := context.Background()
	engine := benchmark.NewEngine()

	requiredCategories := []benchmark.AttackCategory{
		benchmark.CategoryTTYHijacking,
		benchmark.CategoryReverseShell,
		benchmark.CategoryMetadataExfil,
		benchmark.CategoryInternalSubnet,
		benchmark.CategorySlopsquatting,
		benchmark.CategoryForkBomb,
		benchmark.CategoryMemoryExhaustion,
		benchmark.CategorySecretExfiltration,
		benchmark.CategoryPathTraversal,
	}

	categoryCounts := make(map[benchmark.AttackCategory]int)
	for _, v := range engine.Catalog() {
		categoryCounts[v.Category]++
	}

	for _, cat := range requiredCategories {
		count := categoryCounts[cat]
		if count == 0 {
			t.Errorf("missing coverage for required attack category: %q", cat)
		}

		// Filter and evaluate category
		report, err := engine.Run(ctx, benchmark.EngineConfig{
			Concurrency:    2,
			Strict:         true,
			CategoryFilter: string(cat),
		})
		if err != nil {
			t.Fatalf("failed to run category %q: %v", cat, err)
		}

		if report.AllowedCount > 0 || report.DetectionRate != 100.0 {
			t.Errorf("category %q failed defense: %d bypassed out of %d",
				cat, report.AllowedCount, report.TotalVectors)
		}
	}
}

// TestEvasionMatrix_MitreMappingIntegrity ensures every vector adheres to MITRE ATT&CK schema.
func TestEvasionMatrix_MitreMappingIntegrity(t *testing.T) {
	engine := benchmark.NewEngine()
	catalog := engine.Catalog()

	for _, v := range catalog {
		if !strings.HasPrefix(v.MitreID, "T") {
			t.Errorf("vector %s has invalid MITRE ID %q (must start with T)", v.ID, v.MitreID)
		}
		if v.MitreTactic == "" {
			t.Errorf("vector %s missing MITRE tactic", v.ID)
		}
		if v.ExpectedSeverity != "HIGH" && v.ExpectedSeverity != "MEDIUM" {
			t.Errorf("vector %s has unexpected severity %q", v.ID, v.ExpectedSeverity)
		}
	}
}

// mockBypassEvaluator simulates an engine component allowing an exploit.
type mockBypassEvaluator struct{}

func (m *mockBypassEvaluator) Analyze(ctx context.Context, cmdStr string) (*argus.ASTReport, error) {
	return &argus.ASTReport{
		Command:  cmdStr,
		Allowed:  true,
		Findings: nil,
	}, nil
}

type mockNoContainmentEvaluator struct{}

func (m *mockNoContainmentEvaluator) EvaluateContainment(ctx context.Context, vector benchmark.TestVector) (bool, string, string, error) {
	return false, "None", "No containment applied", nil
}

// TestEvasionMatrix_StrictModeFailure verifies that strict mode properly fails when a bypass occurs.
func TestEvasionMatrix_StrictModeFailure(t *testing.T) {
	ctx := context.Background()

	mockEngine := benchmark.NewEngine(
		benchmark.WithAnalyzer(&mockBypassEvaluator{}),
		benchmark.WithSandboxEvaluator(&mockNoContainmentEvaluator{}),
	)

	report, err := mockEngine.Run(ctx, benchmark.EngineConfig{
		Concurrency: 2,
		Strict:      true,
	})
	if err != nil {
		t.Fatalf("unexpected error running mock engine: %v", err)
	}

	if report.Passed {
		t.Errorf("expected strict mode benchmark to FAIL when all vectors bypass defenses")
	}

	if report.DetectionRate != 0.0 {
		t.Errorf("expected 0.0%% detection rate with bypass evaluator, got %.2f%%", report.DetectionRate)
	}

	if report.AllowedCount != report.TotalVectors {
		t.Errorf("expected all vectors to be allowed with bypass evaluator")
	}
}

// TestEvasionMatrix_ScorecardAndJSONOutput tests the formatting methods.
func TestEvasionMatrix_ScorecardAndJSONOutput(t *testing.T) {
	ctx := context.Background()
	engine := benchmark.NewEngine()

	report, err := engine.Run(ctx, benchmark.EngineConfig{
		Concurrency: 4,
		Strict:      true,
	})
	if err != nil {
		t.Fatalf("failed to run engine: %v", err)
	}

	scorecard := report.FormatScorecard()
	if !strings.Contains(scorecard, "AEGISBOX ADVERSARIAL BENCHMARK SCORECARD") {
		t.Errorf("scorecard missing header")
	}
	if !strings.Contains(scorecard, "BENCHMARK EXECUTIVE SUMMARY") {
		t.Errorf("scorecard missing summary section")
	}
	if !strings.Contains(scorecard, "Detection Rate:        100.0%") {
		t.Errorf("scorecard missing 100.0%% detection rate")
	}

	jsonData, err := report.ToJSON()
	if err != nil {
		t.Fatalf("failed to generate JSON: %v", err)
	}

	var parsed benchmark.SuiteReport
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("generated invalid JSON: %v", err)
	}

	if parsed.TotalVectors != report.TotalVectors {
		t.Errorf("JSON parsed total vectors mismatch: expected %d, got %d", report.TotalVectors, parsed.TotalVectors)
	}
	if parsed.DetectionRate != 100.0 {
		t.Errorf("JSON parsed detection rate mismatch: expected 100.0, got %f", parsed.DetectionRate)
	}
}

// TestEvasionMatrix_ContextCancellation verifies that context cancellation stops execution cleanly.
func TestEvasionMatrix_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	engine := benchmark.NewEngine()
	report, err := engine.Run(ctx, benchmark.EngineConfig{
		Concurrency: 4,
	})
	if err != nil {
		t.Fatalf("unexpected run error under cancellation: %v", err)
	}

	// Should finish without deadlock and record cancellation status
	if report.TotalVectors != len(engine.Catalog()) {
		t.Errorf("expected report to account for all catalog items, got %d", report.TotalVectors)
	}
}
