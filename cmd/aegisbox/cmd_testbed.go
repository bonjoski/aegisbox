package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/bonjoski/aegisbox/pkg/adversarial"
)

func runTest(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required: 'aegisbox test range'")
	}

	switch args[0] {
	case "range":
		return runTestRange(ctx, args[1:])
	default:
		return fmt.Errorf("unknown test subcommand %q (supported: range)", args[0])
	}
}

func runTestRange(ctx context.Context, args []string) error {
	rangeFlags := flag.NewFlagSet("test range", flag.ContinueOnError)
	scenario := rangeFlags.String("scenario", "artex-machine-speed", "Adversarial testbed scenario to execute (e.g. artex-machine-speed)")
	strict := rangeFlags.Bool("strict", false, "Enforce strict zero-bypass evaluation (fail if any core security invariant fails)")
	jsonOutput := rangeFlags.Bool("json", false, "Output results in JSON format")
	rate := rangeFlags.Int("rate", 2900, "Simulated credential spray rate per minute")
	thresholdMs := rangeFlags.Int("threshold-ms", 500, "Maximum allowable trip threshold in milliseconds for velocity killswitch")

	rangeFlags.Usage = func() {
		fmt.Println("Usage: aegisbox test range [flags]")
		rangeFlags.PrintDefaults()
	}

	if err := rangeFlags.Parse(args); err != nil {
		return err
	}

	cfg := adversarial.RangeConfig{
		Scenario:            *scenario,
		Strict:              *strict,
		SprayRatePerMin:     *rate,
		VelocityThresholdMs: time.Duration(*thresholdMs) * time.Millisecond,
	}

	engine := adversarial.NewRangeEngine(cfg)
	report, err := engine.Run(ctx)
	if err != nil {
		return fmt.Errorf("adversarial range execution error: %w", err)
	}

	if *jsonOutput {
		jsonData, err := report.ToJSON()
		if err != nil {
			return fmt.Errorf("failed to encode report as JSON: %w", err)
		}
		fmt.Println(string(jsonData))
	} else {
		fmt.Println(report.FormatSummary())
	}

	if *strict && !report.Passed {
		return fmt.Errorf("adversarial testbed range failed: core security invariants violated in strict mode")
	}

	return nil
}
