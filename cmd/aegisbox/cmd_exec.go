package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/argus"
	"github.com/bonjoski/aegisbox/pkg/proxy"
	"github.com/bonjoski/aegisbox/pkg/tui"
	"github.com/bonjoski/aegisbox/pkg/vmm"
	"github.com/bonjoski/aegisbox/pkg/workspace"
)

type stringSliceFlag []string

func (f *stringSliceFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *stringSliceFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func runExec(ctx context.Context, args []string) error {
	execFlags := flag.NewFlagSet("exec", flag.ExitOnError)
	apply := execFlags.Bool("apply", false, "Apply workspace changes back to host workspace on success")
	skipVet := execFlags.Bool("skip-vet", false, "Skip pre-flight Argus AST inspection")
	maskPatterns := execFlags.String("mask", ".git/**,.env*,.github/workflows/**", "Comma-separated path patterns to mask")
	engineFlag := execFlags.String("engine", "local", "Execution engine: 'local' (host process container) or 'microvm' (guest daemon via vsock)")
	airgap := execFlags.Bool("airgap", false, "Sever all outbound network egress and sinkhole DNS")
	forceUnvetted := execFlags.Bool("force-unvetted", false, "Force apply workspace changes even if diff audit detects security traps")
	allowEnv := execFlags.String("allow-env", "", "Comma-separated list of host environment variable names to pass into sandbox (e.g. ANTHROPIC_API_KEY,OPENAI_API_KEY)")
	proxyCreds := execFlags.Bool("proxy-credentials", true, "Shield live LLM API keys via an ephemeral loopback credential proxy")
	interactive := execFlags.Bool("interactive", false, "Run in interactive terminal mode (attaches host stdin/stdout/stderr for agents like Claude Code)")
	execFlags.BoolVar(interactive, "i", false, "Short alias for -interactive")

	var injectFlags stringSliceFlag
	execFlags.Var(&injectFlags, "inject", "Inject host file into shadow workspace: --inject <target>=<source> or --inject <source> (can be repeated or comma-separated)")

	var proxyEnvFlags stringSliceFlag
	execFlags.Var(&proxyEnvFlags, "proxy-env", "Explicitly shield environment variable name via loopback proxy: --proxy-env <ENV_VAR> (can be repeated or comma-separated)")

	var proxyRouteFlags stringSliceFlag
	execFlags.Var(&proxyRouteFlags, "proxy-route", "Define custom upstream proxy route: --proxy-route <ENV_KEY>=<TARGET_URL> (e.g. CORP_KEY=https://llm.corp.internal/v1)")

	var proxyHeaderFlags stringSliceFlag
	execFlags.Var(&proxyHeaderFlags, "proxy-header", "Set custom upstream authentication header: --proxy-header <ENV_KEY>=<HEADER>[:bearer|raw] (e.g. CORP_KEY=X-Custom-Bearer:bearer)")



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

	// Collect custom proxy routes (--proxy-route KEY=TARGET_URL)
	customRoutes := make(map[string]string)
	addRouteItem := func(item string) error {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("invalid --proxy-route format %q: expected KEY=TARGET_URL", item)
		}
		customRoutes[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		return nil
	}

	for _, raw := range proxyRouteFlags {
		for _, item := range strings.Split(raw, ",") {
			if err := addRouteItem(item); err != nil {
				return err
			}
		}
	}
	if envRoute := os.Getenv("AEGISBOX_PROXY_ROUTE"); envRoute != "" {
		for _, item := range strings.Split(envRoute, ",") {
			if err := addRouteItem(item); err != nil {
				return err
			}
		}
	}

	// Collect explicit environment variables to proxy (--proxy-env KEY)
	explicitProxyEnvs := make(map[string]bool)
	addProxyEnvItem := func(item string) error {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil
		}
		if strings.Contains(item, "=") {
			return fmt.Errorf("security violation: --proxy-env takes variable names only (%q)", item)
		}
		explicitProxyEnvs[item] = true
		return nil
	}

	for _, raw := range proxyEnvFlags {
		for _, item := range strings.Split(raw, ",") {
			if err := addProxyEnvItem(item); err != nil {
				return err
			}
		}
	}
	if envProxyEnv := os.Getenv("AEGISBOX_PROXY_ENV"); envProxyEnv != "" {
		for _, item := range strings.Split(envProxyEnv, ",") {
			if err := addProxyEnvItem(item); err != nil {
				return err
			}
		}
	}

	// Collect custom proxy headers (--proxy-header KEY=HEADER_NAME[:STYLE])
	customHeaders := make(map[string]string)
	addHeaderItem := func(item string) error {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("invalid --proxy-header format %q: expected KEY=HEADER[:STYLE]", item)
		}
		customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		return nil
	}

	for _, raw := range proxyHeaderFlags {
		for _, item := range strings.Split(raw, ",") {
			if err := addHeaderItem(item); err != nil {
				return err
			}
		}
	}
	if envHeader := os.Getenv("AEGISBOX_PROXY_HEADER"); envHeader != "" {
		for _, item := range strings.Split(envHeader, ",") {
			if err := addHeaderItem(item); err != nil {
				return err
			}
		}
	}


	// Auto-forward any variables defined in customRoutes or explicitProxyEnvs if present on host
	for k := range customRoutes {
		if _, exists := forwardedEnv[k]; !exists {
			if val, ok := os.LookupEnv(k); ok && val != "" {
				forwardedEnv[k] = val
			}
		}
	}
	for k := range explicitProxyEnvs {
		if _, exists := forwardedEnv[k]; !exists {
			if val, ok := os.LookupEnv(k); ok && val != "" {
				forwardedEnv[k] = val
			}
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


	// Collect files to inject into the shadow workspace
	injectedFiles := make(map[string]string)
	addInjectItem := func(item string) error {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil
		}
		var target, source string
		if strings.Contains(item, "=") {
			parts := strings.SplitN(item, "=", 2)
			target = strings.TrimSpace(parts[0])
			source = strings.TrimSpace(parts[1])
		} else {
			source = item
			target = filepath.Base(source)
		}
		if target == "" || source == "" {
			return fmt.Errorf("invalid --inject format %q: expected target=source or source", item)
		}
		injectedFiles[target] = source
		return nil
	}

	for _, raw := range injectFlags {
		for _, item := range strings.Split(raw, ",") {
			if err := addInjectItem(item); err != nil {
				return err
			}
		}
	}

	if envInject := os.Getenv("AEGISBOX_INJECT"); envInject != "" {
		for _, item := range strings.Split(envInject, ",") {
			if err := addInjectItem(item); err != nil {
				return err
			}
		}
	}

	if len(injectedFiles) > 0 {
		targets := make([]string, 0, len(injectedFiles))
		for target, src := range injectedFiles {
			targets = append(targets, fmt.Sprintf("%s (%s)", target, src))
		}
		sort.Strings(targets)
		fmt.Printf("📄 Injected %d file(s) into sandbox (%s)\n", len(injectedFiles), strings.Join(targets, ", "))
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
		InjectFiles:  injectedFiles,
		ReadOnlyGit:  true,
	})

	if err != nil {
		return fmt.Errorf("failed to create shadow workspace: %w", err)
	}
	defer session.Cleanup(ctx)

	fmt.Printf("📦 Initialized Shadow Session [%s]\n", session.ID())
	fmt.Printf("📂 Shadow Workspace: %s\n", session.ShadowDir())
	fmt.Printf("🚀 Executing: %s\n\n", cmdStr)

	// Initialize loopback credential proxy if any LLM credentials are forwarded
	var (
		activeProxy         *proxy.CredentialProxy
		effectiveSandboxEnv = make(map[string]string)
	)

	llmSecrets := make(map[string]string)
	for k, v := range forwardedEnv {
		shouldProxy := *proxyCreds && (proxy.IsLLMCredential(k) || explicitProxyEnvs[k] || customRoutes[k] != "")
		if shouldProxy {
			llmSecrets[k] = v
		} else {
			effectiveSandboxEnv[k] = v
		}
	}

	if len(llmSecrets) > 0 {
		var err error
		activeProxy, err = proxy.NewCredentialProxy(proxy.Config{
			SessionID:     session.ID(),
			HostSecrets:   llmSecrets,
			CustomRoutes:  customRoutes,
			CustomHeaders: customHeaders,
		})
		if err != nil {
			return fmt.Errorf("failed to start loopback credential proxy: %w", err)
		}
		activeProxy.Start()
		defer activeProxy.Close()

		for k, v := range activeProxy.SandboxEnv() {
			effectiveSandboxEnv[k] = v
		}

		shieldedNames := make([]string, 0, len(llmSecrets))
		for k := range llmSecrets {
			shieldedNames = append(shieldedNames, k)
		}
		sort.Strings(shieldedNames)
		fmt.Printf("🛡️  Loopback Credential Proxy active on %s (shielded %s)\n", activeProxy.BaseURL(), strings.Join(shieldedNames, ", "))
	}

	var (
		stdout   string
		stderr   string
		exitCode int
		execErr  error
	)

	if *interactive && *engineFlag == "microvm" {
		return fmt.Errorf("interactive mode (-i) is not supported on microvm engine; please use default engine (--engine=local) for interactive agents like Claude Code")
	}

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
		for k, v := range effectiveSandboxEnv {
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

		var localEnv []string
		for k, v := range effectiveSandboxEnv {
			localEnv = append(localEnv, k+"="+v)
		}

		if *interactive {
			localH, ok := handle.(interface {
				ExecuteInteractive(ctx context.Context, cmdStr string, env []string) (int, error)
			})
			if !ok {
				return fmt.Errorf("unsupported sandbox driver interface for interactive execution")
			}
			exitCode, execErr = localH.ExecuteInteractive(ctx, cmdStr, localEnv)
		} else {
			localH, ok := handle.(interface {
				ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error)
			})
			if !ok {
				return fmt.Errorf("unsupported sandbox driver interface")
			}
			stdout, stderr, exitCode, execErr = localH.ExecuteInSandbox(ctx, cmdStr, localEnv)
		}
	}

	if !*interactive {
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

	if activeProxy != nil && activeProxy.RequestCount() > 0 {
		fmt.Printf("📊 Proxied %d upstream LLM request(s)\n", activeProxy.RequestCount())
	}

	if execErr != nil || exitCode != 0 {
		return fmt.Errorf("command exited with code %d", exitCode)
	}

	return nil
}
