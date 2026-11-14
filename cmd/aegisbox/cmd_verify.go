package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bonjoski/aegisbox/pkg/verify"
)

func runVerify(ctx context.Context, args []string) error {
	verifyFlags := flag.NewFlagSet("verify", flag.ContinueOnError)
	sarifPath := verifyFlags.String("sarif", "", "Path to SARIF 2.1.0 report file (Snyk, Wiz, Trivy, Endor Labs)")
	workspace := verifyFlags.String("workspace", ".", "Target repository workspace root")
	concurrency := verifyFlags.Int("concurrency", 4, "Maximum concurrent microVM verification slots (default 4)")
	strict := verifyFlags.Bool("strict", false, "Fail with exit code 2 if any finding is confirmed exploitable")
	jsonOutput := verifyFlags.Bool("json", false, "Output verification results in JSON format")

	verifyFlags.Usage = func() {
		fmt.Println("Usage: aegisbox verify --sarif <file.sarif> [--workspace <path>] [--concurrency 4] [--strict] [--json]")
		verifyFlags.PrintDefaults()
	}

	if err := verifyFlags.Parse(args); err != nil {
		return err
	}

	if *sarifPath == "" {
		verifyFlags.Usage()
		return fmt.Errorf("--sarif <path> is required")
	}

	findings, err := verify.ParseSARIFFile(*sarifPath)
	if err != nil {
		return fmt.Errorf("failed parsing SARIF findings: %w", err)
	}

	if len(findings) == 0 {
		if *jsonOutput {
			fmt.Println("[]")
		} else {
			fmt.Println("No findings detected in SARIF document.")
		}
		return nil
	}

	pipeline := verify.NewVerificationPipeline(*concurrency, 30*time.Second, *strict)
	results, err := pipeline.BatchVerify(ctx, *workspace, findings)
	if err != nil && *strict {
		return fmt.Errorf("verification pipeline aborted: %w", err)
	}

	exploitableCount := 0
	for _, r := range results {
		if r.Verdict == verify.VerdictExploitable {
			exploitableCount++
		}
	}

	if *jsonOutput {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("failed marshaling JSON output: %w", err)
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("Aegisbox Open Verification Pipeline: %d findings evaluated\n", len(results))
		fmt.Printf("Workspace: %s | Max VM Concurrency: %d\n\n", *workspace, *concurrency)

		for i, r := range results {
			fmt.Printf("[%d] Rule: %s | CWE-%d | File: %s:%d\n", i+1, r.Finding.RuleID, r.Finding.CWE, r.Finding.FilePath, r.Finding.StartLine)
			fmt.Printf("    Verdict:   %s (%v)\n", r.Verdict, r.ExecutionDuration.Round(time.Millisecond))
			fmt.Printf("    MicroVM:   %s\n", r.MicroVMID)
			fmt.Printf("    Trace:     %s\n", r.PayloadTrace)
			if r.RemediationRecommendation != "" {
				fmt.Printf("    Remedy:    %s\n", r.RemediationRecommendation)
			}
			fmt.Println()
		}

		fmt.Printf("Summary: %d Confirmed Exploitable, %d False Positives/Mitigated\n",
			exploitableCount, len(results)-exploitableCount)
	}

	if *strict && exploitableCount > 0 {
		os.Exit(2)
	}

	return nil
}
