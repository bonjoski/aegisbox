package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bonjoski/aegisbox/pkg/argus"
	"github.com/bonjoski/aegisbox/pkg/netgate"
	"github.com/bonjoski/aegisbox/pkg/policy"
	"github.com/bonjoski/aegisbox/pkg/proxy"
	"github.com/bonjoski/aegisbox/pkg/pty"
	"github.com/bonjoski/aegisbox/pkg/telemetry"
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

// IsDangerousEnvVar checks for dangerous dynamic linker or interpreter hijacking variables.
func IsDangerousEnvVar(name string) bool {
	return policy.IsDangerousEnvVar(name)
}

func shellQuoteArgv(argv []string) string {
	quoted := make([]string, 0, len(argv))
	for _, a := range argv {
		if a == "" {
			quoted = append(quoted, "''")
			continue
		}
		needsQuote := false
		for _, r := range a {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
				r == '_' || r == '-' || r == '.' || r == '/' || r == ':' || r == '@' || r == '=') {
				needsQuote = true
				break
			}
		}
		if !needsQuote {
			quoted = append(quoted, a)
		} else {
			quoted = append(quoted, "'"+strings.ReplaceAll(a, "'", `'\''`)+"'")
		}
	}
	return strings.Join(quoted, " ")
}

func runExec(ctx context.Context, args []string) error {
	execFlags := flag.NewFlagSet("exec", flag.ExitOnError)
	apply := execFlags.Bool("apply", false, "Apply workspace changes back to host workspace on success")
	skipVet := execFlags.Bool("skip-vet", false, "Skip pre-flight Argus AST inspection")
	maskPatterns := execFlags.String("mask", ".git/**,.env*,.github/workflows/**", "Comma-separated path patterns to mask")
	engineFlag := execFlags.String("engine", "microvm", "Execution engine: 'microvm' (hardware-isolated microVM, default), 'airlock' (Tier-1 kernel sandbox), or 'local' (requires --allow-degraded-local)")
	allowDegradedLocal := execFlags.Bool("allow-degraded-local", false, "Explicitly permit degraded host-OS sandbox fallback when hardware microVM isolation is unavailable")
	profileFlag := execFlags.String("profile", "", "Security & registry profile: 'standard', 'permissive', 'microvm-hardened', 'go', 'rust', 'node', 'python', 'strict', or 'airgap'")
	mountCache := execFlags.Bool("mount-cache", false, "Mount host language caches read-only with ephemeral write-staging overlay (Go, Rust, Node, Python)")
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
	execFlags.Var(&proxyRouteFlags, "proxy-route", "Define custom upstream proxy route: --proxy-route <ENV_KEY>=<TARGET_URL> (e.g. CORP_KEY=https://llm.corp.example.com/v1)")

	var proxyHeaderFlags stringSliceFlag
	execFlags.Var(&proxyHeaderFlags, "proxy-header", "Set custom upstream authentication header: --proxy-header <ENV_KEY>=<HEADER>[:bearer|raw] (e.g. CORP_KEY=X-Custom-Bearer:bearer)")

	execFlags.Usage = func() {
		fmt.Println("Usage: aegisbox exec [flags] \"<command>\"")
		execFlags.PrintDefaults()
	}

	if err := execFlags.Parse(args); err != nil {
		return err
	}

	switch *engineFlag {
	case "local", "microvm", "airlock":
	default:
		return fmt.Errorf("unknown execution engine %q (expected 'microvm', 'airlock', or 'local')", *engineFlag)
	}

	var profileAllowedDomains []string
	if *profileFlag != "" {
		switch *profileFlag {
		case "microvm-hardened":
			if *engineFlag == "local" {
				*engineFlag = "microvm"
			}
		case "permissive":
		case "standard", "go", "rust", "node", "python", "strict", "airgap":
			domains, err := policy.ResolveProfileDomains(*profileFlag)
			if err != nil {
				return err
			}
			profileAllowedDomains = domains
			if *profileFlag == "airgap" {
				*airgap = true
			}
		default:
			return fmt.Errorf("unknown security profile %q (expected 'standard', 'permissive', 'microvm-hardened', 'go', 'rust', 'node', 'python', 'strict', or 'airgap')", *profileFlag)
		}
	}

	cmdArgs := execFlags.Args()
	if len(cmdArgs) > 0 && cmdArgs[0] == "--" {
		cmdArgs = cmdArgs[1:]
	}
	if len(cmdArgs) < 1 {
		execFlags.Usage()
		return fmt.Errorf("no command provided to execute")
	}

	// Build structured argv without unquoted strings.Join shell flattening
	var (
		execArgv    []string
		auditCmdStr string
	)
	if len(cmdArgs) == 1 {
		auditCmdStr = cmdArgs[0]
		execArgv = []string{"/bin/sh", "-c", cmdArgs[0]}
	} else {
		execArgv = append([]string(nil), cmdArgs...)
		auditCmdStr = shellQuoteArgv(cmdArgs)
	}

	// Enforce fail-closed engine check before provisioning shadow workspace
	if *engineFlag == "local" && !*allowDegradedLocal {
		return fmt.Errorf("security violation: --engine=local requires explicit --allow-degraded-local flag (hardware microVM isolation is required by default)")
	}

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

	forwardedEnv := make(map[string]string)
	for _, name := range allowedVarNames {
		if strings.Contains(name, "=") {
			return fmt.Errorf("security violation: --allow-env takes variable names only, do not pass secret values or '=' on command line (%q)", name)
		}
		if IsDangerousEnvVar(name) {
			return fmt.Errorf("security violation: refusing to forward dangerous runtime injection environment variable %q", name)
		}
		if val, ok := os.LookupEnv(name); ok && val != "" {
			forwardedEnv[name] = val
		}
	}

	// Collect and validate custom proxy routes (--proxy-route KEY=TARGET_URL)
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
		envKey := strings.TrimSpace(parts[0])
		targetURL := strings.TrimSpace(parts[1])
		if IsDangerousEnvVar(envKey) {
			return fmt.Errorf("security violation: refusing dangerous proxy route variable %q", envKey)
		}
		if err := proxy.ValidateProxyRouteURL(targetURL); err != nil {
			return err
		}
		customRoutes[envKey] = targetURL
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
		if IsDangerousEnvVar(item) {
			return fmt.Errorf("security violation: refusing to proxy dangerous runtime injection environment variable %q", item)
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

	// 1. Pre-flight AST & Package Slopsquatting Gate
	if !*skipVet {
		analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict).WithPackageVerifier(argus.NewPublicRegistryVerifier())
		report, err := analyzer.Analyze(ctx, auditCmdStr)
		if err != nil {
			telemetry.Log("exec", fmt.Sprintf("Argus pre-flight audit failed: %v", err), "stderr")
			return fmt.Errorf("pre-flight audit failed: %w", err)
		}
		if !report.Allowed {
			telemetry.LogTripwire("exec", fmt.Sprintf("Pre-flight BLOCKED: %s", report.Findings[0].Description), "169.254.169.254")
			return fmt.Errorf("pre-flight check failed: command blocked due to high-severity finding (%s)", report.Findings[0].Description)
		}
		telemetry.Log("exec", fmt.Sprintf("Argus AST pre-flight approved command: %s", auditCmdStr), "mcp")
	}

	// Verify hardware hypervisor availability BEFORE creating shadow workspaces or claiming isolation
	useDegradedLocal := *engineFlag == "local"
	if *engineFlag == "microvm" {
		if hwErr := vmm.NewPlatformDriver().VerifyPrerequisites(ctx); hwErr != nil {
			if !*allowDegradedLocal {
				return fmt.Errorf("hardware microVM isolation unavailable (refusing silent fallback to host execution; pass --allow-degraded-local to explicitly permit degraded host sandbox): %w", hwErr)
			}
			fmt.Fprintf(os.Stderr, "⚠️  Hardware hypervisor unavailable (%v); using degraded local sandbox (--allow-degraded-local)\n", hwErr)
			useDegradedLocal = true
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
	go mgr.Scavenge(24 * time.Hour)

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
		InjectFiles: injectedFiles,
		ReadOnlyGit: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create shadow workspace: %w", err)
	}
	defer session.Cleanup(ctx)

	fmt.Printf("📦 Initialized Shadow Session [%s]\n", session.ID())
	fmt.Printf("📂 Shadow Workspace: %s\n", session.ShadowDir())
	fmt.Printf("🚀 Executing: %s\n\n", auditCmdStr)
	telemetry.Log("exec", fmt.Sprintf("CoW Shadow Session [%s] active: %s", session.ID(), session.ShadowDir()), "stdout")
	telemetry.Log("exec", fmt.Sprintf("Executing in sandbox: %s", auditCmdStr), "stdout")

	if mkErr := os.MkdirAll(filepath.Join(session.ShadowDir(), "tmp"), 0700); mkErr != nil {
		return fmt.Errorf("failed to create isolated shadow scratch directory: %w", mkErr)
	}

	var (
		cacheMgr   *workspace.CacheManager
		stagingCfg *workspace.StagingConfig
	)
	if *mountCache {
		cacheMgr = workspace.NewCacheManager()
		stagingDir := filepath.Join(session.ShadowDir(), ".aegisbox-cache-staging")
		var stageErr error
		stagingCfg, stageErr = cacheMgr.ProvisionStaging(stagingDir)
		if stageErr != nil {
			return fmt.Errorf("failed to provision cache staging: %w", stageErr)
		}
		fmt.Println("⚡ Mounted Host Language Caches (Read-Only) with Ephemeral Staging")
	}

	var (
		activeProxy         *proxy.CredentialProxy
		effectiveSandboxEnv = map[string]string{
			"TMPDIR": filepath.Join(session.ShadowDir(), "tmp"),
		}
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

	if stagingCfg != nil {
		for k, v := range stagingCfg.EnvVars {
			effectiveSandboxEnv[k] = v
		}
	}

	if len(llmSecrets) > 0 {
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
		telemetry.Log("exec", fmt.Sprintf("Loopback Credential Proxy active on %s (shielding %d API keys)", activeProxy.BaseURL(), len(llmSecrets)), "mcp")
	}

	var (
		stdout   string
		stderr   string
		exitCode int
		execErr  error
	)

	if *interactive && *engineFlag == "microvm" && !useDegradedLocal {
		return fmt.Errorf("interactive mode (-i) is not supported on microvm engine; pass --engine=airlock or --allow-degraded-local for interactive TTY sessions")
	}

	// Enforce host firewall pinning BEFORE claiming Airgap / Network Pinning is active!
	if *airgap && !useDegradedLocal {
		gov := netgate.NewPlatformGovernor()
		if pinErr := gov.ApplyPinning(ctx, session.ID(), netgate.TargetRule{Airgap: true, BlockDNS: true}, netgate.CanaryConfig{}); pinErr != nil {
			return fmt.Errorf("host airgap firewall pinning failed (refusing unpinned execution): %w", pinErr)
		}
		defer gov.RevokePinning(ctx, session.ID())
		fmt.Println("🌐 Airgap active: outbound network egress severed and DNS sinkholed")
		telemetry.Log("exec", "Airgap active: all outbound network egress severed and DNS sinkholed", "netgate")
	} else if *airgap && useDegradedLocal {
		// In degraded local mode, Seatbelt `(deny network*)` / Airlock `--airgap` enforces kernel socket airgap;
		// attempt host pfctl/nft pinning as defense-in-depth if privileged, otherwise rely on kernel sandbox airgap.
		gov := netgate.NewPlatformGovernor()
		if pinErr := gov.ApplyPinning(ctx, session.ID(), netgate.TargetRule{Airgap: true, BlockDNS: true}, netgate.CanaryConfig{}); pinErr == nil {
			defer gov.RevokePinning(ctx, session.ID())
		}
		fmt.Println("🌐 Sandbox Airgap active: kernel network syscalls denied inside confinement")
		telemetry.Log("exec", "Sandbox Airgap active: kernel network syscalls denied", "netgate")
	} else if len(profileAllowedDomains) > 0 && *engineFlag != "airlock" {
		gov := netgate.NewPlatformGovernor()
		if pinErr := gov.ApplyPinning(ctx, session.ID(), netgate.TargetRule{AllowedDomains: profileAllowedDomains}, netgate.CanaryConfig{}); pinErr != nil {
			return fmt.Errorf("profile network pinning failed (refusing unpinned execution): %w", pinErr)
		}
		defer gov.RevokePinning(ctx, session.ID())
		fmt.Printf("🌐 Profile Network Pinning [%s]: restricted to %d registry domains\n", *profileFlag, len(profileAllowedDomains))
		telemetry.Log("exec", fmt.Sprintf("Profile %s pinning active: restricted to %d domains", *profileFlag, len(profileAllowedDomains)), "netgate")
	}

	if *engineFlag == "microvm" && !useDegradedLocal {
		runner := vmm.NewGuestRunner("")
		guestHandle, err := runner.SpawnGuest(ctx, vmm.VMConfig{
			ID:             session.ID(),
			WorkspaceMount: session.ShadowDir(),
			Airgap:         *airgap,
		})
		if err != nil {
			return fmt.Errorf("failed to spawn microvm guest: %w", err)
		}
		defer guestHandle.Kill(ctx)

		if hb, err := guestHandle.EnableSignalBridge(ctx); err == nil {
			telemetry.Log("exec", "Bidirectional vsock signal bridge attached on port 0x5161", "audit")
			go func() {
				select {
				case oomScore, ok := <-hb.OOMChan():
					if ok {
						telemetry.Log("exec", fmt.Sprintf("⚠️ MicroVM guest OOM killer event triggered (score: %d)", oomScore), "security")
					}
				case <-ctx.Done():
				}
			}()
		}

		fmt.Println("⚡ Initializing MicroVM Guest Daemon via VSock RPC...")

		guestEnv := map[string]string{
			"AEGISBOX_SANDBOX": "1",
			"API_KEY":          "sk-dummy-test-value-0000",
		}
		for k, v := range effectiveSandboxEnv {
			guestEnv[k] = v
		}

		res, err := guestHandle.ExecuteInGuest(ctx, auditCmdStr, guestEnv)
		if err != nil {
			return fmt.Errorf("microvm guest execution failed: %w", err)
		}
		stdout = res.Stdout
		stderr = res.Stderr
		exitCode = res.ExitCode
	} else if *engineFlag == "airlock" {
		fmt.Println("🚀 Delegating Tier-1 Confinement to Airlock Engine...")
		telemetry.Log("exec", "Airlock engine active: sub-15ms zero-VM supervisor execution", "audit")
		var airlockIn *os.File
		if *interactive {
			if !pty.IsStdinTerminal() {
				fmt.Fprintln(os.Stderr, "⚠️  Warning: Stdin is not attached to an interactive terminal")
			}
			airlockIn = os.Stdin
		}
		exitCode, execErr = vmm.ExecuteAirlock(ctx, vmm.AirlockOpts{
			WorkspaceRoot:  cwd,
			WorkingDir:     session.ShadowDir(),
			Airgap:         *airgap,
			Profile:        *profileFlag,
			AllowedDomains: profileAllowedDomains,
			Interactive:    *interactive,
			Stdin:          airlockIn,
			Stdout:         os.Stdout,
			Stderr:         os.Stderr,
		}, cmdArgs)
	} else {
		// Explicitly authorized degraded local sandbox execution (--allow-degraded-local)
		driver := vmm.NewLocalProcessDriver()
		handle, err := driver.SpawnVM(ctx, vmm.VMConfig{
			ID:                 session.ID(),
			WorkspaceMount:     session.ShadowDir(),
			Airgap:             *airgap,
			AllowDegradedLocal: true,
		})
		if err != nil {
			return fmt.Errorf("failed to initialize degraded local sandbox execution: %w", err)
		}
		defer handle.Kill(ctx)

		var localEnv []string
		for k, v := range effectiveSandboxEnv {
			localEnv = append(localEnv, k+"="+v)
		}

		if *interactive {
			if !pty.IsStdinTerminal() {
				fmt.Fprintln(os.Stderr, "⚠️  Warning: Stdin is not attached to an interactive terminal")
			}
			localH, ok := handle.(interface {
				ExecuteArgvInteractive(ctx context.Context, argv []string, env []string) (int, error)
			})
			if !ok {
				return fmt.Errorf("unsupported sandbox driver interface for interactive execution")
			}
			exitCode, execErr = localH.ExecuteArgvInteractive(ctx, execArgv, localEnv)
		} else {
			localH, ok := handle.(interface {
				ExecuteArgvInSandbox(ctx context.Context, argv []string, env []string) (string, string, int, error)
			})
			if !ok {
				return fmt.Errorf("unsupported sandbox driver interface")
			}
			stdout, stderr, exitCode, execErr = localH.ExecuteArgvInSandbox(ctx, execArgv, localEnv)
		}
	}

	if !*interactive {
		sanitizer := tui.NewTerminalSanitizer()
		for _, v := range forwardedEnv {
			sanitizer.AddSecretToRedact(v)
		}
		if activeProxy != nil {
			sanitizer.AddSecretToRedact(activeProxy.ProxyToken())
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
		telemetry.Log("exec", fmt.Sprintf("Workspace delta: +%d added, ~%d modified, -%d deleted", len(diff.FilesAdded), len(diff.FilesModified), len(diff.FilesDeleted)), "stdout")
		for _, f := range diff.FilesAdded {
			fmt.Printf("  + [ADD] %s\n", f)
		}
		for _, f := range diff.FilesModified {
			fmt.Printf("  ~ [MOD] %s\n", f)
		}
		for _, f := range diff.FilesDeleted {
			fmt.Printf("  - [DEL] %s\n", f)
		}

		diffAuditor := argus.NewSemanticDiffAuditor(cwd)
		changed := append(diff.FilesAdded, diff.FilesModified...)
		auditReport, auditErr := diffAuditor.AuditFiles(ctx, session.ShadowDir(), changed)
		if auditErr == nil && len(auditReport.Findings) > 0 {
			fmt.Printf("\n🛡️  Semantic Diff Audit: %d findings detected\n", len(auditReport.Findings))
			for _, f := range auditReport.Findings {
				fmt.Printf("  ⚠️  [%s] %s: %s\n", f.Severity, f.File, f.Description)
				telemetry.LogTripwire("exec", fmt.Sprintf("Diff Audit trap detected: %s (%s)", f.Description, f.File), "169.254.169.254")
			}
		}

		if *apply && exitCode == 0 {
			fmt.Println("💾 Applying changes back to host workspace...")
			if *forceUnvetted {
				if fa, ok := session.(workspace.ForceApplier); ok {
					if err := fa.ApplyToHostForceUnvetted(ctx); err != nil {
						return fmt.Errorf("failed to apply changes: %w", err)
					}
				} else if err := session.ApplyToHost(ctx); err != nil {
					return fmt.Errorf("failed to apply changes: %w", err)
				}
			} else {
				if err := session.ApplyToHost(ctx); err != nil {
					return fmt.Errorf("apply aborted: %w", err)
				}
			}
			if *mountCache && cacheMgr != nil && stagingCfg != nil {
				userHome, _ := os.UserHomeDir()
				if userHome != "" {
					_ = cacheMgr.SyncBack(stagingCfg.BaseDir, userHome)
				}
			}
			fmt.Println("✅ Changes successfully applied.")
		} else if !*apply {
			fmt.Println("ℹ️  Changes were isolated in shadow workspace and NOT written to host (pass --apply to persist).")
		}
	}

	if activeProxy != nil && activeProxy.RequestCount() > 0 {
		fmt.Printf("📊 Proxied %d upstream LLM request(s)\n", activeProxy.RequestCount())
		telemetry.Log("exec", fmt.Sprintf("Proxied %d upstream LLM API requests via loopback credential shield", activeProxy.RequestCount()), "mcp")
	}

	telemetry.Log("exec", fmt.Sprintf("Sandbox command finished with exit code %d", exitCode), "stdout")

	if execErr != nil || exitCode != 0 {
		return fmt.Errorf("command exited with code %d", exitCode)
	}

	return nil
}
