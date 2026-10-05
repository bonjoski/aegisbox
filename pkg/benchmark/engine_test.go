package benchmark_test

import (
	"context"
	"testing"
	"time"

	"github.com/bonjoski/aegisbox/pkg/benchmark"
)

func TestEngine_DefaultCatalog(t *testing.T) {
	engine := benchmark.NewEngine()
	catalog := engine.Catalog()

	if len(catalog) < 15 {
		t.Fatalf("expected at least 15 default test vectors, got %d", len(catalog))
	}

	seenIDs := make(map[string]bool)
	for _, v := range catalog {
		if seenIDs[v.ID] {
			t.Errorf("duplicate vector ID found: %s", v.ID)
		}
		seenIDs[v.ID] = true

		if v.ID == "" || v.Name == "" || v.Category == "" || v.Command == "" || v.MitreID == "" {
			t.Errorf("vector %s has missing required metadata", v.ID)
		}
	}
}

func TestEngine_ExecutionOptions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	engine := benchmark.NewEngine()

	// Concurrency 1
	report1, err := engine.Run(ctx, benchmark.EngineConfig{
		Concurrency: 1,
		Strict:      true,
	})
	if err != nil {
		t.Fatalf("run with concurrency=1 failed: %v", err)
	}
	if report1.DetectionRate != 100.0 {
		t.Errorf("expected 100%% detection, got %.1f%%", report1.DetectionRate)
	}

	// Concurrency 8
	report8, err := engine.Run(ctx, benchmark.EngineConfig{
		Concurrency: 8,
		Strict:      true,
	})
	if err != nil {
		t.Fatalf("run with concurrency=8 failed: %v", err)
	}
	if report8.DetectionRate != 100.0 {
		t.Errorf("expected 100%% detection, got %.1f%%", report8.DetectionRate)
	}
}

func TestEngine_CustomCatalog(t *testing.T) {
	ctx := context.Background()

	customCatalog := []benchmark.TestVector{
		{
			ID:               "CUSTOM-001",
			Name:             "Custom Subnet Probe",
			Category:         benchmark.CategoryInternalSubnet,
			Command:          "curl -s http://192.168.1.100/admin",
			MitreID:          "T1046",
			MitreTactic:      "Discovery",
			ExpectedSeverity: "HIGH",
		},
	}

	engine := benchmark.NewEngine(benchmark.WithCatalog(customCatalog))
	if len(engine.Catalog()) != 1 {
		t.Fatalf("expected 1 custom vector, got %d", len(engine.Catalog()))
	}

	report, err := engine.Run(ctx, benchmark.EngineConfig{Strict: true})
	if err != nil {
		t.Fatalf("custom run failed: %v", err)
	}

	if report.TotalVectors != 1 || report.BlockedCount != 1 || !report.Passed {
		t.Errorf("unexpected custom suite report: %+v", report)
	}
}
