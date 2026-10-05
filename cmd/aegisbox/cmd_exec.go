package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/argus"
	"github.com/bonjoski/aegisbox/pkg/tui"
	"github.com/bonjoski/aegisbox/pkg/vmm"
	"github.com/bonjoski/aegisbox/pkg/workspace"
)

func runExec(ctx context.Context, args []string) error {
	execFlags := flag.NewFlagSet("exec", flag.ExitOnError)
	apply := execFlags.Bool("apply", false, "Apply workspace changes back to host workspace on success")
	skipVet := execFlags.Bool("skip-vet", false, "Skip pre-flight Argus AST inspection")
	maskPatterns := execFlags.String("mask", ".git/**,.env*,.github/workflows/**", "Comma-separated path patterns to mask")
	engineFlag := execFlags.String("engine", "local", "Execution engine: 'local' (host process container) or 'microvm' (guest daemon via vsock)")
	airgap := execFlags.Bool("airgap", false, "Sever all outbound network egress and sinkhole DNS")
	forceUnvetted := execFlags.Bool("force-unvetted", false, "Force apply workspace changes even if diff audit detects security traps")

	execFlags.Usage = func() {
		fmt.Println("Usage: aegisbox exec [flags] \"<command>\"")
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
			"AEGISBOX_SANDBOX": "1",
			"API_KEY":          "sk-dummy-test-value-0000",
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

	var (
		stdout   string
		stderr   string
		exitCode int
		execErr  error
	)

	if *engineFlag == "microvm" {
		fmt.Println("⚡ Initializing MicroVM Guest Daemon via VSock RPC...")
		runner := vmm.NewGuestRunner("")
		guestHandle, err := runner.SpawnGuest(ctx, vmm.VMConfig{
			ID:             session.ID(),
			WorkspaceMount: session.ShadowDir(),
		})
		if err != nil {
			return fmt.Errorf("failed to spawn microvm guest: %w", err)
		}
		defer guestHandle.Kill(ctx)

		res, err := guestHandle.ExecuteInGuest(ctx, cmdStr, map[string]string{
			"AEGISBOX_SANDBOX": "1",
			"API_KEY":          "sk-dummy-test-value-0000",
		})
		if err != nil {
			return fmt.Errorf("microvm guest execution failed: %w", err)
		}
		stdout = res.Stdout
		stderr = res.Stderr
		exitCode = res.ExitCode
	} else {
		// Default local process driver
		driver := vmm.NewLocalProcessDriver()
		handle, err := driver.SpawnVM(ctx, vmm.VMConfig{
			ID:             session.ID(),
			WorkspaceMount: session.ShadowDir(),
		})
		if err != nil {
			return fmt.Errorf("failed to initialize sandbox execution: %w", err)
		}

		localH, ok := handle.(interface {
			ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error)
		})
		if !ok {
			return fmt.Errorf("unsupported sandbox driver interface")
		}

		stdout, stderr, exitCode, execErr = localH.ExecuteInSandbox(ctx, cmdStr, nil)
	}

	sanitizer := tui.NewTerminalSanitizer()
	if stdout != "" {
		fmt.Print(sanitizer.SanitizeString(stdout))
	}
	if stderr != "" {
		fmt.Fprint(os.Stderr, sanitizer.SanitizeString(stderr))
	}

	// 4. Capture Diff Report & Perform Semantic Diff Audit
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

		// Semantic Diff Weaponization Audit
		diffAuditor := argus.NewSemanticDiffAuditor(cwd)
		changed := append(diff.FilesAdded, diff.FilesModified...)
		auditReport, auditErr := diffAuditor.AuditFiles(ctx, session.ShadowDir(), changed)
		if auditErr == nil && len(auditReport.Findings) > 0 {
			fmt.Printf("\n🛡️  Semantic Diff Audit: %d findings detected\n", len(auditReport.Findings))
			for _, f := range auditReport.Findings {
				fmt.Printf("  ⚠️  [%s] %s: %s\n", f.Severity, f.File, f.Description)
			}
		}

		if *apply && exitCode == 0 {
			if auditReport != nil && !auditReport.Allowed && !*forceUnvetted {
				return fmt.Errorf("apply aborted: semantic diff audit detected high-risk execution traps (pass --force-unvetted to override)")
			}

			fmt.Println("💾 Applying changes back to host workspace...")
			if err := session.ApplyToHost(ctx); err != nil {
				return fmt.Errorf("failed to apply changes: %w", err)
			}
			fmt.Println("✅ Changes successfully applied.")
		} else if !*apply {
			fmt.Println("ℹ️  Changes were isolated in shadow workspace and NOT written to host (pass --apply to persist).")
		}
	}

	_ = airgap // Referenced flag

	if execErr != nil || exitCode != 0 {
		return fmt.Errorf("command exited with code %d", exitCode)
	}

	return nil
}
