package matrix

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMatrixRunner_DefaultSample(t *testing.T) {
	manifest := DefaultSampleManifest()
	runner := NewMatrixRunner(4)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	report, err := runner.Run(ctx, manifest)
	if err != nil {
		t.Fatalf("matrix run failed: %v", err)
	}

	if report.TotalTasks != len(manifest.Tasks) {
		t.Errorf("expected %d tasks, got %d", len(manifest.Tasks), report.TotalTasks)
	}

	if report.Violations > 0 {
		t.Errorf("expected 0 violations, got %d", report.Violations)
	}

	if report.SuccessRate != 100.0 {
		t.Errorf("expected 100.0%% success rate, got %.1f%%", report.SuccessRate)
	}

	table := report.FormatTable()
	if !strings.Contains(table, "EVALUATION MATRIX SUMMARY") {
		t.Errorf("expected table summary in output")
	}

	md := report.FormatMarkdown()
	if !strings.Contains(md, "Aegisbox Multi-Agent Evaluation Report") {
		t.Errorf("expected markdown report in output")
	}
}

func TestSimpleYAMLParser(t *testing.T) {
	yamlContent := `
name: Test Manifest
tasks:
  - id: TEST-01
    name: Test Task
    command: echo hello
    expected_status: allowed
`
	m, err := parseSimpleYAML(yamlContent)
	if err != nil {
		t.Fatalf("failed to parse simple yaml: %v", err)
	}

	if len(m.Tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(m.Tasks))
	}
	if m.Tasks[0].ID != "TEST-01" {
		t.Errorf("expected ID 'TEST-01', got %q", m.Tasks[0].ID)
	}
	if m.Tasks[0].Command != "echo hello" {
		t.Errorf("expected command 'echo hello', got %q", m.Tasks[0].Command)
	}
}
