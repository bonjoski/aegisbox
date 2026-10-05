package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/bonjoski/aegisbox/pkg/benchmark"
)

func runBenchmark(ctx context.Context, args []string) error {
	benchFlags := flag.NewFlagSet("benchmark", flag.ExitOnError)
	concurrency := benchFlags.Int("concurrency", 4, "Number of concurrent evaluation workers")
	jsonOutput := benchFlags.Bool("json", false, "Output results in JSON format")
	outputFile := benchFlags.String("output", "", "Write scorecard or JSON report to specified file")
	strict := benchFlags.Bool("strict", false, "Enforce strict zero-evasion (fail if any adversarial vector passes)")

	benchFlags.Usage = func() {
		fmt.Println("Usage: aegisbox benchmark [flags]")
		benchFlags.PrintDefaults()
	}

	if err := benchFlags.Parse(args); err != nil {
		return err
	}

	engine := benchmark.NewEngine()
	report, err := engine.Run(ctx, benchmark.EngineConfig{
		Concurrency: *concurrency,
		Strict:      *strict,
	})
	if err != nil {
		return fmt.Errorf("benchmark execution failed: %w", err)
	}

	var outputContent string
	if *jsonOutput {
		jsonBytes, err := report.ToJSON()
		if err != nil {
			return fmt.Errorf("failed to serialize benchmark report to JSON: %w", err)
		}
		outputContent = string(jsonBytes)
	} else {
		outputContent = report.FormatScorecard()
	}

	if *outputFile != "" {
		if err := os.WriteFile(*outputFile, []byte(outputContent), 0644); err != nil {
			return fmt.Errorf("failed to write report to %q: %w", *outputFile, err)
		}
		if !*jsonOutput {
			fmt.Printf("📄 Benchmark report saved to %s\n\n", *outputFile)
		}
	}

	fmt.Println(outputContent)

	if *strict && !report.Passed {
		return fmt.Errorf("adversarial benchmark failed: %d vector(s) bypassed defenses (strict mode active)", report.AllowedCount)
	}

	return nil
}
