package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bonjoski/ironbox/pkg/argus"
	"github.com/bonjoski/ironbox/pkg/vmm"
	"github.com/bonjoski/ironbox/pkg/workspace"
)

func runExec(ctx context.Context, args []string) error {
	execFlags := flag.NewFlagSet("exec", flag.ExitOnError)
	apply := execFlags.Bool("apply", false, "Apply workspace changes back to host workspace on success")
	skipVet := execFlags.Bool("skip-vet", false, "Skip pre-flight Argus AST inspection")
	maskPatterns := execFlags.String("mask", ".git/**,.env*,.github/workflows/**", "Comma-separated path patterns to mask")

	execFlags.Usage = func() {
		fmt.Println("Usage: ironbox exec [flags] \"<command>\"")
		execFlags.PrintDefaults()
	}

	if err := execFlags.Parse(args); err != nil {
		return err
	}

	cmdArgs := execFlags.Args()
	if len(cmdArgs) < 1 {
		execFlags.Usage()
		return fmt.Errorf("no command provided to execute")
	}

	cmdStr := strings.Join(cmdArgs, " ")

	// 1. Pre-flight AST Gate
	if !*skipVet {
		analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict)
		report, err := analyzer.Analyze(ctx, cmdStr)
		if err != nil {
			return fmt.Errorf("pre-flight audit failed: %w", err)
		}
		if !report.Allowed {
			return fmt.Errorf("pre-flight check failed: command blocked due to high-severity finding (%s)", report.Findings[0].Description)
		}
	}

	// 2. Initialize Ephemeral Shadow Workspace
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	mgr, err := workspace.NewWorkspaceManager("")
	if err != nil {
		return fmt.Errorf("failed to initialize workspace manager: %w", err)
	}

	var masks []string
	if *maskPatterns != "" {
		masks = strings.Split(*maskPatterns, ",")
	}

	session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir:      cwd,
		Mode:         workspace.ModeGitWorktree,
		MaskPatterns: masks,
		SyntheticEnv: map[string]string{
			"IRONBOX_SANDBOX": "1",
			"API_KEY":         "sk-dummy-test-value-0000",
		},
		ReadOnlyGit: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create shadow workspace: %w", err)
	}
	defer session.Cleanup(ctx)

	fmt.Printf("📦 Initialized Shadow Session [%s]\n", session.ID())
	fmt.Printf("📂 Shadow Workspace: %s\n", session.ShadowDir())
	fmt.Printf("🚀 Executing: %s\n\n", cmdStr)

	// 3. Execute inside local/sandbox driver
	driver := vmm.NewLocalProcessDriver()
	handle, err := driver.SpawnVM(ctx, vmm.VMConfig{
		ID:             session.ID(),
		WorkspaceMount: session.ShadowDir(),
	})
	if err != nil {
		return fmt.Errorf("failed to initialize sandbox execution: %w", err)
	}

	// Run command
	localH, ok := handle.(interface {
		ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error)
	})
	if !ok {
		return fmt.Errorf("unsupported sandbox driver interface")
	}

	stdout, stderr, exitCode, execErr := localH.ExecuteInSandbox(ctx, cmdStr, nil)
	if stdout != "" {
		fmt.Print(stdout)
	}
	if stderr != "" {
		fmt.Fprint(os.Stderr, stderr)
	}

	// 4. Capture Diff Report
	diff, err := session.CaptureDiff(ctx)
	if err == nil && (len(diff.FilesAdded) > 0 || len(diff.FilesModified) > 0 || len(diff.FilesDeleted) > 0) {
		fmt.Printf("\n📝 Workspace Delta Captured:\n")
		for _, f := range diff.FilesAdded {
			fmt.Printf("  + [ADD] %s\n", f)
		}
		for _, f := range diff.FilesModified {
			fmt.Printf("  ~ [MOD] %s\n", f)
		}
		for _, f := range diff.FilesDeleted {
			fmt.Printf("  - [DEL] %s\n", f)
		}

		if *apply && exitCode == 0 {
			fmt.Println("💾 Applying changes back to host workspace...")
			if err := session.ApplyToHost(ctx); err != nil {
				return fmt.Errorf("failed to apply changes: %w", err)
			}
			fmt.Println("✅ Changes successfully applied.")
		} else if !*apply {
			fmt.Println("ℹ️  Changes were isolated in shadow workspace and NOT written to host (pass --apply to persist).")
		}
	}

	if execErr != nil || exitCode != 0 {
		return fmt.Errorf("command exited with code %d", exitCode)
	}

	return nil
}
