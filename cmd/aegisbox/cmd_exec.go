package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
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
	allowEnv := execFlags.String("allow-env", "", "Comma-separated list of host environment variable names to pass into sandbox (e.g. ANTHROPIC_API_KEY,OPENAI_API_KEY)")

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

	// Collect and validate environment variables to forward into the sandbox
	var allowedVarNames []string
	if *allowEnv != "" {
		for _, v := range strings.Split(*allowEnv, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				allowedVarNames = append(allowedVarNames, v)
			}
		}
	}
	if envVar := os.Getenv("AEGISBOX_ALLOW_ENV"); envVar != "" {
		for _, v := range strings.Split(envVar, ",") {
			v = strings.TrimSpace(v)
			if v != "" {
				allowedVarNames = append(allowedVarNames, v)
			}
		}
	}

	// Security validation: verify no secret values or '=' are passed in CLI arguments
	forwardedEnv := make(map[string]string)
	for _, name := range allowedVarNames {
		if strings.Contains(name, "=") {
			return fmt.Errorf("security violation: --allow-env takes variable names only, do not pass secret values or '=' on command line (%q)", name)
		}
		if val, ok := os.LookupEnv(name); ok && val != "" {
			forwardedEnv[name] = val
		}
	}

	if len(forwardedEnv) > 0 {
		names := make([]string, 0, len(forwardedEnv))
		for k := range forwardedEnv {
			names = append(names, k)
		}
		sort.Strings(names)
		fmt.Printf("🔐 Forwarded %d environment variable(s) into sandbox (%s)\n", len(forwardedEnv), strings.Join(names, ", "))
	}

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

		guestEnv := map[string]string{
			"AEGISBOX_SANDBOX": "1",
			"API_KEY":          "sk-dummy-test-value-0000",
		}
		for k, v := range forwardedEnv {
			guestEnv[k] = v
		}

		res, err := guestHandle.ExecuteInGuest(ctx, cmdStr, guestEnv)
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

		var localEnv []string
		for k, v := range forwardedEnv {
			localEnv = append(localEnv, k+"="+v)
		}

		stdout, stderr, exitCode, execErr = localH.ExecuteInSandbox(ctx, cmdStr, localEnv)
	}

	sanitizer := tui.NewTerminalSanitizer()
	for _, v := range forwardedEnv {
		sanitizer.AddSecretToRedact(v)
	}
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
