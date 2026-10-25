package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/argus"
	"github.com/bonjoski/aegisbox/pkg/telemetry"
)

func runVet(ctx context.Context, args []string) error {
	vetFlags := flag.NewFlagSet("vet", flag.ExitOnError)
	checkPkgs := vetFlags.Bool("check-pkgs", true, "Perform live registry check for hallucinated packages")
	vetFlags.Usage = func() {
		fmt.Println("Usage: aegisbox vet [flags] \"<command string>\"")
		vetFlags.PrintDefaults()
	}

	if err := vetFlags.Parse(args); err != nil {
		return err
	}

	cmdArgs := vetFlags.Args()
	if len(cmdArgs) < 1 {
		vetFlags.Usage()
		return fmt.Errorf("no command string provided to vet")
	}

	cmdStr := cmdArgs[0]
	fmt.Printf("🛡️  Aegisbox Pre-Flight Vet (Argus Engine)\nCommand: %s\n\n", cmdStr)
	telemetry.Log("vet", fmt.Sprintf("Argus AST pre-flight analyzing command: %s", cmdStr), "mcp")

	analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict)
	report, err := analyzer.Analyze(ctx, cmdStr)
	if err != nil {
		telemetry.Log("vet", fmt.Sprintf("Argus pre-flight analysis failed: %v", err), "stderr")
		return fmt.Errorf("pre-flight analysis failed: %w", err)
	}

	if len(report.Findings) > 0 {
		fmt.Printf("🚨 Security Findings (%d):\n", len(report.Findings))
		for i, f := range report.Findings {
			fmt.Printf("  [%d] [%s] %s: %s\n      Matched: %s\n", i+1, f.Severity, f.RuleID, f.Description, f.MatchedText)
			target := "169.254.169.254"
			if strings.Contains(f.MatchedText, "http") || strings.Contains(f.MatchedText, "169.") || strings.Contains(f.MatchedText, "10.") {
				target = strings.TrimPrefix(strings.TrimPrefix(f.MatchedText, "http://"), "https://")
			}
			telemetry.LogTripwire("vet", fmt.Sprintf("Argus Rule %s: %s (matched: %s)", f.RuleID, f.Description, f.MatchedText), target)
		}
	} else {
		fmt.Println("  ✅ No AST or pattern anomalies detected.")
	}

	if *checkPkgs && len(report.ExtractedPkgs) > 0 {
		fmt.Printf("\n📦 Inspecting Extracted Packages (%d):\n", len(report.ExtractedPkgs))
		verifier := argus.NewPublicRegistryVerifier()
		for _, pkg := range report.ExtractedPkgs {
			res, err := verifier.VerifyPackage(ctx, pkg)
			if err != nil {
				fmt.Printf("  ⚠️  [%s] %s: Lookup error: %v\n", pkg.Ecosystem, pkg.Name, err)
				continue
			}
			if !res.ExistsInIndex {
				fmt.Printf("  ❌ [%s] %s: NOT FOUND (Potential hallucinated package / slopsquat!)\n", pkg.Ecosystem, pkg.Name)
				telemetry.LogTripwire("vet", fmt.Sprintf("Hallucinated package / slopsquat blocked: [%s] %s", pkg.Ecosystem, pkg.Name), "registry."+pkg.Ecosystem+".org")
				report.Allowed = false
			} else {
				fmt.Printf("  ✅ [%s] %s: Verified in official registry\n", pkg.Ecosystem, pkg.Name)
			}
		}
	}

	fmt.Println()
	if report.Allowed {
		fmt.Println("🎉 Verdict: ALLOWED. Safe to proceed inside sandbox.")
		telemetry.Log("vet", fmt.Sprintf("Argus AST VERDICT: ALLOWED for command: %s", cmdStr), "stdout")
		return nil
	}

	fmt.Println("⛔ Verdict: BLOCKED. Command violates security policies.")
	telemetry.Log("vet", fmt.Sprintf("Argus AST VERDICT: BLOCKED for command: %s", cmdStr), "tripwire")
	os.Exit(2)
	return nil
}
