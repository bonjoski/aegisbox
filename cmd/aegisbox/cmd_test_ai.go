package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/aegisbox/pkg/aisafety"
)

func runTestAISafety(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("test --ai-safety", flag.ContinueOnError)
	_ = fs.Bool("ai-safety", true, "Run local AI-safety adversarial unit-test harness")
	target := fs.String("target", "", "Strictly local HTTP endpoint (http://127.0.0.1:<port>/..., http://localhost:<port>/..., or http://[::1]:<port>/...)")
	mcpCmd := fs.String("mcp-cmd", "", "Local MCP STDIO server command to test (e.g. \"node ./dist/mcp-server.js\")")
	cliCmd := fs.String("cli-cmd", "", "Local CLI command to test via JSON stdin")
	categoriesFlag := fs.String("categories", "", "Comma-separated probe categories to run (default: all 6)")
	probesFile := fs.String("probes-file", "", "Optional JSON custom probe pack (max 256KB, <=64 probes, os.OpenRoot symlink-safe)")
	why := fs.Bool("why", false, "Include full threat breakdown and real-world precedent for proven failures")
	jsonOut := fs.Bool("json", false, "Output structured JSON report")
	allowDegradedLocal := fs.Bool("allow-degraded-local", false, "Explicitly permit degraded Tier-1 local containment when hardware microVM is unavailable")
	timeout := fs.Duration("timeout", 30*time.Second, "Maximum per-suite execution timeout")
	traceDir := fs.String("trace-dir", "", "Override Flightdeck JSONL trace directory")

	fs.Usage = func() {
		fmt.Println("Usage: aegisbox test --ai-safety (--target <local-url> | --mcp-cmd <cmd>) [--probes-file <path>] [--why] [--json] [--allow-degraded-local]")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	spec := aisafety.TargetSpec{
		Timeout:            *timeout,
		AllowDegradedLocal: *allowDegradedLocal,
		TraceDir:           *traceDir,
	}

	switch {
	case strings.TrimSpace(*target) != "":
		spec.Kind = aisafety.TargetKindHTTPLocal
		spec.Endpoint = strings.TrimSpace(*target)
	case strings.TrimSpace(*mcpCmd) != "":
		argv, err := splitCommandLine(*mcpCmd)
		if err != nil {
			return fmt.Errorf("invalid --mcp-cmd: %w", err)
		}
		spec.Kind = aisafety.TargetKindMCPStdio
		spec.Command = argv
	case strings.TrimSpace(*cliCmd) != "":
		argv, err := splitCommandLine(*cliCmd)
		if err != nil {
			return fmt.Errorf("invalid --cli-cmd: %w", err)
		}
		spec.Kind = aisafety.TargetKindCLILocal
		spec.Command = argv
	default:
		return fmt.Errorf("target required: pass --target <http://127.0.0.1:PORT/...> or --mcp-cmd \"<local-mcp-server>\"")
	}

	var categories []aisafety.ProbeCategory
	if strings.TrimSpace(*categoriesFlag) != "" {
		for _, part := range strings.Split(*categoriesFlag, ",") {
			p := strings.TrimSpace(part)
			if p != "" {
				categories = append(categories, aisafety.ProbeCategory(p))
			}
		}
	}

	harness := aisafety.NewDefaultHarness()
	if strings.TrimSpace(*probesFile) != "" {
		customProbes, err := aisafety.LoadCustomProbes(*probesFile)
		if err != nil {
			return fmt.Errorf("failed loading --probes-file: %w", err)
		}
		harness.Probes = append(harness.Probes, customProbes...)
	}
	report, err := harness.RunSuiteWithReport(ctx, spec, categories)
	if err != nil {
		return err
	}

	if *jsonOut {
		data, err := aisafety.FormatReportJSON(report)
		if err != nil {
			return fmt.Errorf("failed to encode AI-safety report as JSON: %w", err)
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(aisafety.FormatReport(report, *why))
	}

	if report.ProvenFailures > 0 {
		return fmt.Errorf("ai-safety suite failed with %d proven failure(s) (replay: flightdeck replay %s)", report.ProvenFailures, report.ReplayTraceID)
	}
	return nil
}

// splitCommandLine splits a command string into argv without performing any shell/env expansion.
func splitCommandLine(raw string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	for _, r := range raw {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && !inSingle {
			escaped = true
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if (r == ' ' || r == '\t') && !inSingle && !inDouble {
			if cur.Len() > 0 {
				args = append(args, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if inSingle || inDouble || escaped {
		return nil, fmt.Errorf("unterminated quote or escape in command %q", raw)
	}
	if cur.Len() > 0 {
		args = append(args, cur.String())
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return args, nil
}
