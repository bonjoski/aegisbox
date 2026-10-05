package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/bonjoski/aegisbox/pkg/matrix"
)

func runMatrix(ctx context.Context, args []string) error {
	matrixFlags := flag.NewFlagSet("matrix", flag.ExitOnError)
	manifestPath := matrixFlags.String("manifest", "", "Path to evaluation manifest (JSON or YAML)")
	concurrency := matrixFlags.Int("concurrency", 4, "Number of concurrent worker worktrees")
	format := matrixFlags.String("format", "table", "Output format: 'table', 'markdown', or 'json'")
	outputFile := matrixFlags.String("output", "", "Write report output to specified file")
	sampleFlag := matrixFlags.Bool("sample", false, "Generate sample matrix manifest (matrix.json)")

	matrixFlags.Usage = func() {
		fmt.Println("Usage: aegisbox matrix [flags]")
		matrixFlags.PrintDefaults()
	}

	if err := matrixFlags.Parse(args); err != nil {
		return err
	}

	if *sampleFlag {
		sample := matrix.DefaultSampleManifest()
		data, err := json.MarshalIndent(sample, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile("matrix.json", data, 0644); err != nil {
			return fmt.Errorf("failed to write matrix.json: %w", err)
		}
		fmt.Println("✅ Generated sample evaluation manifest: matrix.json")
		fmt.Println("   Run evaluation via: aegisbox matrix --manifest matrix.json")
		return nil
	}

	var m *matrix.MatrixManifest
	var err error

	if *manifestPath != "" {
		m, err = matrix.LoadManifest(*manifestPath)
		if err != nil {
			return fmt.Errorf("failed to load manifest: %w", err)
		}
	} else {
		fmt.Println("ℹ️  No --manifest provided; running default frontier agent safety evaluation matrix...")
		m = matrix.DefaultSampleManifest()
	}

	fmt.Printf("🚀 Executing Matrix [%s] across %d concurrent shadow worktrees...\n\n", m.Name, *concurrency)

	runner := matrix.NewMatrixRunner(*concurrency)
	report, err := runner.Run(ctx, m)
	if err != nil {
		return fmt.Errorf("matrix execution failed: %w", err)
	}

	var reportStr string
	switch *format {
	case "json":
		data, _ := json.MarshalIndent(report, "", "  ")
		reportStr = string(data)
	case "markdown", "md":
		reportStr = report.FormatMarkdown()
	default:
		reportStr = report.FormatTable()
	}

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(reportStr), 0644); err != nil {
			return fmt.Errorf("failed to write report to %s: %w", *outputFile, err)
		}
		fmt.Printf("💾 Report successfully saved to: %s\n", *outputFile)
	} else {
		fmt.Println(reportStr)
	}

	if report.Violations > 0 {
		return fmt.Errorf("matrix evaluation finished with %d violations", report.Violations)
	}

	return nil
}
