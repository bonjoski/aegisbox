package mcp

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/argus"
	"github.com/bonjoski/aegisbox/pkg/policy"
	"github.com/bonjoski/aegisbox/pkg/proxy"
	"github.com/bonjoski/aegisbox/pkg/tui"
	"github.com/bonjoski/aegisbox/pkg/vmm"
	"github.com/bonjoski/aegisbox/pkg/workspace"
)

// MCPTool defines the schema for an MCP exposed tool.
type MCPTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// ToolConfig controls execution isolation requirements for MCP tool invocations.
type ToolConfig struct {
	AllowDegradedLocal bool
}

// GetAvailableTools returns the list of tools provided by Aegisbox to IDE agents.
func GetAvailableTools() []MCPTool {
	return []MCPTool{
		{
			Name:        "aegisbox_exec",
			Description: "Execute a command inside an isolated shadow workspace with secret path masking and diff capture",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{
						"type":        "string",
						"description": "Shell command to execute inside the sandbox",
					},
					"apply": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, persist modified files back to the host workspace upon success",
					},
				},
				"required": []string{"command"},
			},
		},
		{
			Name:        "aegisbox_vet",
			Description: "Perform pre-flight AST audit and hallucinated package slopsquatting check on a command",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{
						"type":        "string",
						"description": "Shell command string to audit",
					},
				},
				"required": []string{"command"},
			},
		},
		{
			Name:        "aegisbox_diff",
			Description: "Inspect file changes generated during sandboxed execution",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}
}

// HandleToolCall executes the corresponding Aegisbox engine logic in strict fail-closed microVM mode.
func HandleToolCall(ctx context.Context, name string, args map[string]interface{}) (string, error) {
	return HandleToolCallWithConfig(ctx, name, args, ToolConfig{AllowDegradedLocal: false})
}

// HandleToolCallWithConfig executes the corresponding Aegisbox engine logic with explicit isolation settings.
func HandleToolCallWithConfig(ctx context.Context, name string, args map[string]interface{}, cfg ToolConfig) (string, error) {
	switch name {
	case "aegisbox_vet":
		cmdVal, ok := args["command"].(string)
		if !ok || cmdVal == "" {
			return "", fmt.Errorf("missing required 'command' argument")
		}

		analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict).WithPackageVerifier(argus.NewPublicRegistryVerifier())
		report, err := analyzer.Analyze(ctx, cmdVal)
		if err != nil {
			return "", fmt.Errorf("vet analysis failed: %w", err)
		}

		var sb strings.Builder
		if report.Allowed {
			sb.WriteString("✅ Pre-Flight Gate PASSED: Command is safe to execute.\n")
		} else {
			sb.WriteString("⛔ Pre-Flight Gate BLOCKED: Command violates security policies.\n")
		}

		for i, f := range report.Findings {
			sb.WriteString(fmt.Sprintf("  [%d] [%s] %s: %s (Matched: %s)\n", i+1, f.Severity, f.RuleID, f.Description, f.MatchedText))
		}
		return sb.String(), nil

	case "aegisbox_exec":
		cmdVal, ok := args["command"].(string)
		if !ok || cmdVal == "" {
			return "", fmt.Errorf("missing required 'command' argument")
		}
		apply, _ := args["apply"].(bool)

		// 1. Pre-flight AST & Slopsquatting Gate
		analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict).WithPackageVerifier(argus.NewPublicRegistryVerifier())
		report, err := analyzer.Analyze(ctx, cmdVal)
		if err != nil {
			return "", fmt.Errorf("pre-flight check failed: %w", err)
		}
		if !report.Allowed {
			return "", fmt.Errorf("command blocked by Aegisbox security policy: %s", report.Findings[0].Description)
		}

		// 2. Validate AEGISBOX_ALLOW_ENV and AEGISBOX_PROXY_ROUTE before touching host secrets
		hostSecrets := make(map[string]string)
		var secretsToRedact []string
		if allowEnv := os.Getenv("AEGISBOX_ALLOW_ENV"); allowEnv != "" {
			for _, envName := range strings.Split(allowEnv, ",") {
				envName = strings.TrimSpace(envName)
				if envName == "" {
					continue
				}
				if strings.Contains(envName, "=") {
					return "", fmt.Errorf("security violation: AEGISBOX_ALLOW_ENV must contain variable names only (%q)", envName)
				}
				if policy.IsDangerousEnvVar(envName) {
					return "", fmt.Errorf("security violation: refusing to expose dangerous environment variable %q", envName)
				}
				if val, exists := os.LookupEnv(envName); exists && val != "" {
					hostSecrets[envName] = val
					secretsToRedact = append(secretsToRedact, val)
				}
			}
		}

		customRoutes := make(map[string]string)
		if envRoute := os.Getenv("AEGISBOX_PROXY_ROUTE"); envRoute != "" {
			for _, item := range strings.Split(envRoute, ",") {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				parts := strings.SplitN(item, "=", 2)
				if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
					return "", fmt.Errorf("invalid AEGISBOX_PROXY_ROUTE entry %q: expected KEY=HTTPS_URL", item)
				}
				envKey := strings.TrimSpace(parts[0])
				targetURL := strings.TrimSpace(parts[1])
				if policy.IsDangerousEnvVar(envKey) {
					return "", fmt.Errorf("security violation: refusing dangerous proxy route variable %q", envKey)
				}
				if routeErr := proxy.ValidateProxyRouteURL(targetURL); routeErr != nil {
					return "", fmt.Errorf("security violation in AEGISBOX_PROXY_ROUTE: %w", routeErr)
				}
				customRoutes[envKey] = targetURL
				if val, exists := os.LookupEnv(envKey); exists && val != "" {
					hostSecrets[envKey] = val
					secretsToRedact = append(secretsToRedact, val)
				}
			}
		}

		// 3. Verify Hardware Hypervisor Isolation (fail closed unless AllowDegradedLocal is explicitly set)
		hwDriver := vmm.NewPlatformDriver()
		hwErr := hwDriver.VerifyPrerequisites(ctx)
		if hwErr != nil && !cfg.AllowDegradedLocal {
			return "", fmt.Errorf("hardware microVM isolation unavailable (refusing silent downgrade to host process execution; start MCP server with --allow-degraded-local to explicitly permit degraded confinement): %w", hwErr)
		}

		// 4. Workspace setup
		cwd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("failed to get working directory: %w", err)
		}

		mgr, err := workspace.NewWorkspaceManager("")
		if err != nil {
			return "", fmt.Errorf("workspace manager error: %w", err)
		}

		session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
			BaseDir:      cwd,
			Mode:         workspace.ModeGitWorktree,
			MaskPatterns: []string{".git/**", ".env*", ".github/workflows/**"},
			SyntheticEnv: map[string]string{
				"AEGISBOX_SANDBOX": "1",
				"API_KEY":          "sk-mock-dummy-token",
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to create shadow workspace: %w", err)
		}
		defer session.Cleanup(ctx)

		// 5. Route ALL host secrets through CredentialProxy phantom tokens (never inject plaintext secrets!)
		sandboxEnvMap := make(map[string]string)
		var activeProxy *proxy.CredentialProxy
		if len(hostSecrets) > 0 {
			activeProxy, err = proxy.NewCredentialProxy(proxy.Config{
				SessionID:    session.ID(),
				HostSecrets:  hostSecrets,
				CustomRoutes: customRoutes,
			})
			if err != nil {
				return "", fmt.Errorf("failed to start credential proxy: %w", err)
			}
			activeProxy.Start()
			defer activeProxy.Close()

			for k, v := range activeProxy.SandboxEnv() {
				sandboxEnvMap[k] = v
			}
			secretsToRedact = append(secretsToRedact, activeProxy.ProxyToken())
		}

		var (
			stdout   string
			stderr   string
			exitCode int
		)

		if hwErr == nil {
			runner := vmm.NewGuestRunner("")
			guestHandle, spawnErr := runner.SpawnGuest(ctx, vmm.VMConfig{
				ID:             session.ID(),
				WorkspaceMount: session.ShadowDir(),
			})
			if spawnErr != nil {
				return "", fmt.Errorf("microVM spawn error: %w", spawnErr)
			}
			defer guestHandle.Kill(ctx)

			guestRes, execErr := guestHandle.ExecuteInGuest(ctx, cmdVal, sandboxEnvMap)
			if execErr != nil {
				return "", fmt.Errorf("microVM execution error: %w", execErr)
			}
			stdout = guestRes.Stdout
			stderr = guestRes.Stderr
			exitCode = guestRes.ExitCode
		} else {
			localDriver := vmm.NewLocalProcessDriver()
			handle, spawnErr := localDriver.SpawnVM(ctx, vmm.VMConfig{
				ID:                 session.ID(),
				WorkspaceMount:     session.ShadowDir(),
				AllowDegradedLocal: true,
			})
			if spawnErr != nil {
				return "", fmt.Errorf("degraded sandbox spawn error: %w", spawnErr)
			}
			defer handle.Kill(ctx)

			localH, ok := handle.(interface {
				ExecuteArgvInSandbox(ctx context.Context, argv []string, env []string) (string, string, int, error)
			})
			if !ok {
				return "", fmt.Errorf("unsupported local sandbox handle")
			}

			var localEnv []string
			for k, v := range sandboxEnvMap {
				localEnv = append(localEnv, k+"="+v)
			}
			stdout, stderr, exitCode, _ = localH.ExecuteArgvInSandbox(ctx, []string{"/bin/sh", "-c", cmdVal}, localEnv)
		}

		diff, _ := session.CaptureDiff(ctx)

		sanitizer := tui.NewTerminalSanitizer()
		for _, v := range secretsToRedact {
			sanitizer.AddSecretToRedact(v)
		}

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Exit Code: %d\n", exitCode))
		if stdout != "" {
			sb.WriteString(fmt.Sprintf("Stdout:\n%s\n", sanitizer.SanitizeString(stdout)))
		}
		if stderr != "" {
			sb.WriteString(fmt.Sprintf("Stderr:\n%s\n", sanitizer.SanitizeString(stderr)))
		}

		if diff != nil && (len(diff.FilesAdded) > 0 || len(diff.FilesModified) > 0) {
			sb.WriteString("\nWorkspace Changes:\n")
			for _, f := range diff.FilesAdded {
				sb.WriteString(fmt.Sprintf("  + [ADD] %s\n", f))
			}
			for _, f := range diff.FilesModified {
				sb.WriteString(fmt.Sprintf("  ~ [MOD] %s\n", f))
			}

			if apply && exitCode == 0 {
				if applyErr := session.ApplyToHost(ctx); applyErr != nil {
					return "", fmt.Errorf("workspace apply blocked by security gate: %w", applyErr)
				}
				sb.WriteString("  💾 Changes applied to host workspace.\n")
			}
		}

		return sb.String(), nil

	case "aegisbox_diff":
		return "No active detached session found.", nil

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}
