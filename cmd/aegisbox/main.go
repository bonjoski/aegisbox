package main

import (
	"context"
	"fmt"
	"os"
)


func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	ctx := context.Background()
	subcommand := os.Args[1]

	switch subcommand {
	case "doctor":
		if err := runDoctor(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "vet":
		if err := runVet(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "exec":
		if err := runExec(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "range":
		if err := runRange(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "diff":
		if err := runDiff(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "benchmark":
		if err := runBenchmark(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "matrix":
		if err := runMatrix(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "monitor":
		if err := runMonitor(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "mcp":
		if err := runMCP(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "completion":
		if err := runCompletion(ctx, os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "version", "--version", "-v":
		fmt.Println("aegisbox version 0.2.0")
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Aegisbox: Unbreakable AI Execution Sandbox & Adversarial Range Engine

Usage:
  aegisbox <command> [arguments]

Commands:
  doctor     Run diagnostic environment checks (Hypervisor, KVM, Apple VZ, Git, Network)
  vet        Run pre-flight AST analysis and Argus package slopsquatting audit on a command
  exec       Execute a command inside an ephemeral shadowed CoW workspace
  range      Run an adversarial task pinned to a target host with canary tripwires
  benchmark  Run adversarial red-team benchmark evaluation suite against sandbox defenses
  matrix     Run parallel multi-agent evaluation matrix across isolated shadow worktrees
  mcp        Start headless Model Context Protocol server for IDEs (Cursor, Claude, AGY)
  diff       Inspect or apply workspace changes made during an aegisbox session
  monitor    Launch real-time security telemetry & MicroVM resource monitor
  completion Generate shell autocompletion script (bash, zsh, fish)
  version    Show aegisbox version information


Examples:
  aegisbox doctor
  aegisbox vet "pip install torch-hallucinated-package && python3 exploit.py"
  aegisbox exec --apply "go build ./..."
  aegisbox range --target 10.200.5.42:443 -- nmap -p 443 10.200.5.42
  aegisbox benchmark --concurrency=4 --strict`)
}

