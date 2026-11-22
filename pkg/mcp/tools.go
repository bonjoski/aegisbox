package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/argus"
	"github.com/bonjoski/aegisbox/pkg/policy"
	"github.com/bonjoski/aegisbox/pkg/proxy"
	"github.com/bonjoski/aegisbox/pkg/tui"
	"github.com/bonjoski/aegisbox/pkg/ux"
	"github.com/bonjoski/aegisbox/pkg/vmm"
	"github.com/bonjoski/aegisbox/pkg/workspace"
)

// MCPTool defines the schema for an MCP exposed tool.
type MCPTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

// ToolConfig controls execution isolation, signing, and lease redemption settings for MCP tool invocations.
type ToolConfig struct {
	AllowDegradedLocal bool
	LocksmithBroker    *LocksmithBroker
	ReceiptSigner      ReceiptSigner
	ReceiptDir         string
}

// GetAvailableTools returns the harmonized UB-MCP-v1 tools provided by Aegisbox to IDE agents.
func GetAvailableTools() []MCPTool {
	return []MCPTool{
		{
			Name:        "aegisbox_exec",
			Description: "Execute a command inside an isolated shadow workspace with opaque Locksmith secret leases, secret leak blocking, diff capture, and BLPR-v1 receipt emission",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"command": map[string]interface{}{
						"type":        "string",
						"description": "Shell command to execute inside the sandbox",
					},
					"workspace": map[string]interface{}{
						"type":        "string",
						"description": "Optional target workspace directory path to mount into the shadow sandbox",
					},
					"apply": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, persist modified files back to the host workspace upon success",
					},
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Optional Fabrial session correlation ID (e.g. sess_01J...) for opaque lease binding and BLPR-v1 receipts",
					},
					"secret_leases": map[string]interface{}{
						"type":        "array",
						"description": "Opaque Locksmith lease IDs redeemed directly over LOCKSMITH_SOCKET without exposing secret bytes to LLM context",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
					"emit_receipt": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, require emitting a signed BLPR-v1 DSSE receipt under FABRIAL_RECEIPT_DIR",
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
					"workspace": map[string]interface{}{
						"type":        "string",
						"description": "Optional target workspace directory path for receipt correlation",
					},
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Optional Fabrial session correlation ID for BLPR-v1 receipts",
					},
					"emit_receipt": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, require emitting a signed BLPR-v1 DSSE receipt under FABRIAL_RECEIPT_DIR",
					},
				},
				"required": []string{"command"},
			},
		},
		{
			Name:        "aegisbox_diff",
			Description: "Inspect file changes generated during sandboxed execution",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"workspace": map[string]interface{}{
						"type":        "string",
						"description": "Optional target workspace directory path",
					},
					"session_id": map[string]interface{}{
						"type":        "string",
						"description": "Optional Fabrial session correlation ID for BLPR-v1 receipts",
					},
					"emit_receipt": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, require emitting a signed BLPR-v1 DSSE receipt under FABRIAL_RECEIPT_DIR",
					},
				},
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
	if args == nil {
		args = map[string]interface{}{}
	}
	sessionID, _ := args["session_id"].(string)
	emitReceipt, emitSpecified := parseOptionalBool(args, "emit_receipt")
	workspaceArg, _ := args["workspace"].(string)

	switch name {
	case "aegisbox_vet":
		cmdVal, ok := args["command"].(string)
		if !ok || strings.TrimSpace(cmdVal) == "" {
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_INVALID_ARGUMENTS",
				ExitCode:       ExitPolicyDeny,
				Retryable:      true,
				Summary:        "Missing required 'command' argument for aegisbox_vet.",
				RemediationCmd: `aegisbox vet "go test ./..."`,
				Why:            "Pre-flight vetting requires a non-empty shell command string to parse and audit.",
			}
		}

		analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict).WithPackageVerifier(argus.NewPublicRegistryVerifier())
		report, err := analyzer.Analyze(ctx, cmdVal)
		if err != nil {
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_VET_FAILED",
				ExitCode:       ExitSupplyChainBlock,
				Retryable:      false,
				Summary:        fmt.Sprintf("Pre-flight vet analysis failed: %s", ux.SanitizeSingleLine(err.Error())),
				RemediationCmd: `aegisbox vet "go test ./..."`,
				Why:            "Aegisbox fails closed when command AST or package vetting cannot complete.",
			}
		}

		cmdHash := sha256Hex(cmdVal)
		if !report.Allowed {
			findingDesc := "Command violates Aegisbox pre-flight security policy."
			if len(report.Findings) > 0 {
				findingDesc = ux.SanitizeSingleLine(report.Findings[0].Description)
			}
			rcptID := ""
			if !emitSpecified || emitReceipt {
				var rErr error
				rcptID, _, rErr = EmitBLPRReceipt(ctx, ReceiptParams{
					ReceiptDir:     cfg.ReceiptDir,
					SessionID:      sessionID,
					WorkspaceDir:   workspaceArg,
					SubjectName:    "aegisbox_vet",
					SubjectDigest:  cmdHash,
					Verdict:        ReceiptVerdictDeny,
					Proven:         true,
					FixForwardCode: "AEGISBOX_VET_BLOCKED",
					Claims: map[string]interface{}{
						"tool_action":    "aegisbox_vet",
						"findings_count": len(report.Findings),
						"proven_findings": len(report.Findings),
					},
					Signer:       resolveReceiptSigner(cfg),
					ExplicitEmit: emitReceipt,
				})
				if rErr != nil {
					return "", rErr
				}
			}

			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_VET_BLOCKED",
				ExitCode:       ExitSupplyChainBlock,
				Retryable:      true,
				Summary:        fmt.Sprintf("Pre-flight gate blocked command: %s", findingDesc),
				RemediationCmd: "argus vet --strict",
				Why:            "Aegisbox blocks unvetted downloads, dangerous shell AST patterns, and suspected slopsquatted packages before execution.",
				SelfHeal: &SelfHealSuggestion{
					SuggestedTool: "argus_vet",
					SuggestedArgs: map[string]interface{}{
						"strict": true,
					},
					RequiresHumanApproval: false,
				},
				ReceiptID: rcptID,
			}
		}

		if !emitSpecified || emitReceipt {
			if _, _, rErr := EmitBLPRReceipt(ctx, ReceiptParams{
				ReceiptDir:    cfg.ReceiptDir,
				SessionID:     sessionID,
				WorkspaceDir:  workspaceArg,
				SubjectName:   "aegisbox_vet",
				SubjectDigest: cmdHash,
				Verdict:       ReceiptVerdictAllow,
				Proven:        true,
				Claims: map[string]interface{}{
					"tool_action":     "aegisbox_vet",
					"findings_count":  len(report.Findings),
					"proven_findings": 0,
				},
				Signer:       resolveReceiptSigner(cfg),
				ExplicitEmit: emitReceipt,
			}); rErr != nil {
				return "", rErr
			}
		}

		var sb strings.Builder
		sb.WriteString("✅ Pre-Flight Gate PASSED: Command is safe to execute.\n")
		for i, f := range report.Findings {
			sb.WriteString(fmt.Sprintf("  [%d] [%s] %s: %s (Matched: %s)\n",
				i+1,
				ux.SanitizeSingleLine(string(f.Severity)),
				ux.SanitizeSingleLine(f.RuleID),
				ux.SanitizeSingleLine(f.Description),
				ux.SanitizeSingleLine(f.MatchedText),
			))
		}
		return sb.String(), nil

	case "aegisbox_exec":
		cmdVal, ok := args["command"].(string)
		if !ok || strings.TrimSpace(cmdVal) == "" {
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_INVALID_ARGUMENTS",
				ExitCode:       ExitPolicyDeny,
				Retryable:      true,
				Summary:        "Missing required 'command' argument for aegisbox_exec.",
				RemediationCmd: `aegisbox exec "go test ./..."`,
				Why:            "Sandboxed execution requires a non-empty command string.",
			}
		}
		apply, _ := args["apply"].(bool)

		secretLeaseIDs, leaseParseErr := parseStringSliceArg(args, "secret_leases")
		if leaseParseErr != nil {
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_INVALID_SECRET_LEASES",
				ExitCode:       ExitPolicyDeny,
				Retryable:      true,
				Summary:        leaseParseErr.Error(),
				RemediationCmd: "aegisbox explain secrets",
				Why:            "secret_leases must be an array of opaque Locksmith lease IDs.",
			}
		}

		// 1. Pre-flight AST & Slopsquatting Gate
		analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict).WithPackageVerifier(argus.NewPublicRegistryVerifier())
		report, err := analyzer.Analyze(ctx, cmdVal)
		if err != nil {
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_VET_FAILED",
				ExitCode:       ExitSupplyChainBlock,
				Retryable:      false,
				Summary:        fmt.Sprintf("Pre-flight check failed: %s", ux.SanitizeSingleLine(err.Error())),
				RemediationCmd: "argus vet --strict",
				Why:            "Aegisbox fails closed when pre-flight AST or package vetting encounters an error.",
			}
		}
		if !report.Allowed {
			desc := "Command violates Aegisbox pre-flight policy."
			if len(report.Findings) > 0 {
				desc = ux.SanitizeSingleLine(report.Findings[0].Description)
			}
			rcptID := ""
			if !emitSpecified || emitReceipt {
				var rErr error
				rcptID, _, rErr = EmitBLPRReceipt(ctx, ReceiptParams{
					ReceiptDir:     cfg.ReceiptDir,
					SessionID:      sessionID,
					WorkspaceDir:   workspaceArg,
					SubjectName:    "aegisbox_exec",
					SubjectDigest:  sha256Hex(cmdVal),
					Verdict:        ReceiptVerdictDeny,
					Proven:         true,
					FixForwardCode: "AEGISBOX_VET_BLOCKED",
					Claims: map[string]interface{}{
						"tool_action":     "aegisbox_exec",
						"findings_count":  len(report.Findings),
						"proven_findings": len(report.Findings),
					},
					Signer:       resolveReceiptSigner(cfg),
					ExplicitEmit: emitReceipt,
				})
				if rErr != nil {
					return "", rErr
				}
			}
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_VET_BLOCKED",
				ExitCode:       ExitSupplyChainBlock,
				Retryable:      true,
				Summary:        fmt.Sprintf("Command blocked by Aegisbox security policy: %s", desc),
				RemediationCmd: "argus vet --strict",
				Why:            "Commands containing dangerous AST patterns or suspected slopsquatted packages are blocked before sandbox launch.",
				ReceiptID:      rcptID,
			}
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
					return "", &UBMCPError{
						SchemaVersion:  UBMCPSchemaVersion,
						Tool:           BLPRProducerTool,
						Code:           "AEGISBOX_POLICY_DENIED",
						ExitCode:       ExitPolicyDeny,
						Retryable:      false,
						Summary:        fmt.Sprintf("Security violation: AEGISBOX_ALLOW_ENV must contain variable names only (%q).", envName),
						RemediationCmd: "unset AEGISBOX_ALLOW_ENV",
						Why:            "Inline key=value assignments in AEGISBOX_ALLOW_ENV are rejected to prevent environment injection.",
					}
				}
				if policy.IsDangerousEnvVar(envName) {
					return "", &UBMCPError{
						SchemaVersion:  UBMCPSchemaVersion,
						Tool:           BLPRProducerTool,
						Code:           "AEGISBOX_POLICY_DENIED",
						ExitCode:       ExitPolicyDeny,
						Retryable:      false,
						Summary:        fmt.Sprintf("Security violation: refusing to expose dangerous environment variable %q.", envName),
						RemediationCmd: "unset AEGISBOX_ALLOW_ENV",
						Why:            "Loader and runtime override environment variables (such as LD_PRELOAD or DYLD_INSERT_LIBRARIES) are forbidden.",
					}
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
					return "", &UBMCPError{
						SchemaVersion:  UBMCPSchemaVersion,
						Tool:           BLPRProducerTool,
						Code:           "AEGISBOX_POLICY_DENIED",
						ExitCode:       ExitPolicyDeny,
						Retryable:      false,
						Summary:        fmt.Sprintf("Invalid AEGISBOX_PROXY_ROUTE entry %q: expected KEY=HTTPS_URL.", item),
						RemediationCmd: "unset AEGISBOX_PROXY_ROUTE",
						Why:            "Proxy routes must specify an explicit variable name and validated HTTPS upstream endpoint.",
					}
				}
				envKey := strings.TrimSpace(parts[0])
				targetURL := strings.TrimSpace(parts[1])
				if policy.IsDangerousEnvVar(envKey) {
					return "", &UBMCPError{
						SchemaVersion:  UBMCPSchemaVersion,
						Tool:           BLPRProducerTool,
						Code:           "AEGISBOX_POLICY_DENIED",
						ExitCode:       ExitPolicyDeny,
						Retryable:      false,
						Summary:        fmt.Sprintf("Security violation: refusing dangerous proxy route variable %q.", envKey),
						RemediationCmd: "unset AEGISBOX_PROXY_ROUTE",
						Why:            "Dangerous dynamic loader variables cannot be registered as proxy route secrets.",
					}
				}
				if routeErr := proxy.ValidateProxyRouteURL(targetURL); routeErr != nil {
					return "", &UBMCPError{
						SchemaVersion:  UBMCPSchemaVersion,
						Tool:           BLPRProducerTool,
						Code:           "AEGISBOX_POLICY_DENIED",
						ExitCode:       ExitPolicyDeny,
						Retryable:      false,
						Summary:        fmt.Sprintf("Security violation in AEGISBOX_PROXY_ROUTE: %s", ux.SanitizeSingleLine(routeErr.Error())),
						RemediationCmd: "unset AEGISBOX_PROXY_ROUTE",
						Why:            "Proxy route targets must use HTTPS and cannot target private, loopback, or metadata IP ranges.",
					}
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
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_MICROVM_REQUIRED",
				ExitCode:       ExitSandboxViolation,
				Retryable:      false,
				Summary:        fmt.Sprintf("Hardware microVM isolation unavailable (refusing silent downgrade): %s", ux.SanitizeSingleLine(hwErr.Error())),
				RemediationCmd: "aegisbox mcp --allow-degraded-local",
				Why:            "Aegisbox fails closed when hardware virtualization prerequisites are missing instead of silently running on the host.",
			}
		}

		// 4. Redeem opaque Locksmith secret leases directly over LOCKSMITH_SOCKET (zero subprocesses, zeroizable []byte)
		var (
			broker        *LocksmithBroker
			redeemedLease []*SecretLease
		)
		if len(secretLeaseIDs) > 0 {
			broker = cfg.LocksmithBroker
			if broker == nil {
				var bErr error
				broker, bErr = NewLocksmithBroker()
				if bErr != nil {
					return "", &UBMCPError{
						SchemaVersion:  UBMCPSchemaVersion,
						Tool:           BLPRProducerTool,
						Code:           "AEGISBOX_SECRET_LEASE_DENIED",
						ExitCode:       ExitSecretGuardBlock,
						Retryable:      true,
						Summary:        "Locksmith UDS socket could not be resolved for opaque secret_leases.",
						RemediationCmd: `eval "$(fabrial session begin)"`,
						Why:            "Opaque secret leases are redeemed directly over LOCKSMITH_SOCKET without spawning CLI subprocesses.",
					}
				}
			}
			defer broker.RevokeAll()

			for _, lid := range secretLeaseIDs {
				lease, rErr := broker.RedeemOpaqueLease(ctx, lid, sessionID)
				if rErr != nil {
					exitCode := ExitSecretGuardBlock
					code := "AEGISBOX_SECRET_LEASE_DENIED"
					if errors.Is(rErr, ErrBiometricDenied) {
						exitCode = ExitBiometricRequired
						code = "AEGISBOX_BIOMETRIC_REQUIRED"
					}
					return "", &UBMCPError{
						SchemaVersion:  UBMCPSchemaVersion,
						Tool:           BLPRProducerTool,
						Code:           code,
						ExitCode:       exitCode,
						Retryable:      true,
						Summary:        fmt.Sprintf("Failed to redeem opaque secret lease: %s", ux.SanitizeSingleLine(rErr.Error())),
						RemediationCmd: `eval "$(fabrial session begin)"`,
						Why:            "Opaque secret leases must be valid, unexpired, and bound to the active Locksmith session.",
						SelfHeal: &SelfHealSuggestion{
							SuggestedTool: "locksmith_checkout_lease",
							SuggestedArgs: map[string]interface{}{
								"ttl_seconds": 120,
							},
							RequiresHumanApproval: false,
						},
					}
				}
				defer lease.Scrub()
				redeemedLease = append(redeemedLease, lease)
			}
		}

		// 5. Workspace setup (honoring explicit workspace argument if supplied)
		baseDir, err := resolveWorkspaceDir(workspaceArg)
		if err != nil {
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_INVALID_WORKSPACE",
				ExitCode:       ExitPolicyDeny,
				Retryable:      true,
				Summary:        fmt.Sprintf("Invalid workspace path: %s", ux.SanitizeSingleLine(err.Error())),
				RemediationCmd: "pwd",
				Why:            "The workspace argument must reference an existing local directory.",
			}
		}

		mgr, err := workspace.NewWorkspaceManager("")
		if err != nil {
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_SANDBOX_VIOLATION",
				ExitCode:       ExitSandboxViolation,
				Retryable:      false,
				Summary:        fmt.Sprintf("Workspace manager initialization failed: %s", ux.SanitizeSingleLine(err.Error())),
				RemediationCmd: "aegisbox doctor",
				Why:            "Aegisbox requires a writable local shadow session store under ~/.aegisbox/sessions.",
			}
		}

		session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
			BaseDir:      baseDir,
			Mode:         workspace.ModeGitWorktree,
			MaskPatterns: []string{".git/**", ".env*", ".github/workflows/**"},
			SyntheticEnv: map[string]string{
				"AEGISBOX_SANDBOX": "1",
				"API_KEY":          "sk-mock-dummy-token",
			},
		})
		if err != nil {
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_SANDBOX_VIOLATION",
				ExitCode:       ExitSandboxViolation,
				Retryable:      false,
				Summary:        fmt.Sprintf("Failed to create shadow workspace: %s", ux.SanitizeSingleLine(err.Error())),
				RemediationCmd: "aegisbox doctor",
				Why:            "Commands only run inside an isolated shadow copy of the workspace.",
			}
		}
		defer session.Cleanup(ctx)

		// 6. Route host AEGISBOX_ALLOW_ENV secrets through CredentialProxy phantom tokens
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

		// Inject redeemed opaque lease bytes strictly into the isolated execution environment.
		// Build a dedicated slice for local execution and zeroize temporary buffers immediately.
		var (
			stdout    string
			stderr    string
			exitCode  int
			vmBackend string
		)

		if hwErr == nil {
			vmBackend = "microvm"
			for _, lease := range redeemedLease {
				sandboxEnvMap[lease.Key] = string(lease.Bytes())
			}
			runner := vmm.NewGuestRunner("")
			guestHandle, spawnErr := runner.SpawnGuest(ctx, vmm.VMConfig{
				ID:             session.ID(),
				WorkspaceMount: session.ShadowDir(),
			})
			if spawnErr != nil {
				return "", &UBMCPError{
					SchemaVersion:  UBMCPSchemaVersion,
					Tool:           BLPRProducerTool,
					Code:           "AEGISBOX_SANDBOX_VIOLATION",
					ExitCode:       ExitSandboxViolation,
					Retryable:      false,
					Summary:        fmt.Sprintf("microVM spawn error: %s", ux.SanitizeSingleLine(spawnErr.Error())),
					RemediationCmd: "aegisbox doctor",
					Why:            "The hardware microVM guest failed to start.",
				}
			}
			defer guestHandle.Kill(ctx)

			guestRes, execErr := guestHandle.ExecuteInGuest(ctx, cmdVal, sandboxEnvMap)
			if execErr != nil {
				return "", &UBMCPError{
					SchemaVersion:  UBMCPSchemaVersion,
					Tool:           BLPRProducerTool,
					Code:           "AEGISBOX_SANDBOX_VIOLATION",
					ExitCode:       ExitSandboxViolation,
					Retryable:      false,
					Summary:        fmt.Sprintf("microVM execution error: %s", ux.SanitizeSingleLine(execErr.Error())),
					RemediationCmd: "aegisbox doctor",
					Why:            "Command execution inside the isolated microVM guest failed.",
				}
			}
			stdout = guestRes.Stdout
			stderr = guestRes.Stderr
			exitCode = guestRes.ExitCode
		} else {
			vmBackend = "degraded-local"
			localDriver := vmm.NewLocalProcessDriver()
			handle, spawnErr := localDriver.SpawnVM(ctx, vmm.VMConfig{
				ID:                 session.ID(),
				WorkspaceMount:     session.ShadowDir(),
				AllowDegradedLocal: true,
			})
			if spawnErr != nil {
				return "", &UBMCPError{
					SchemaVersion:  UBMCPSchemaVersion,
					Tool:           BLPRProducerTool,
					Code:           "AEGISBOX_SANDBOX_VIOLATION",
					ExitCode:       ExitSandboxViolation,
					Retryable:      false,
					Summary:        fmt.Sprintf("Degraded sandbox spawn error: %s", ux.SanitizeSingleLine(spawnErr.Error())),
					RemediationCmd: "aegisbox doctor",
					Why:            "The local sandbox confinement driver failed to initialize.",
				}
			}
			defer handle.Kill(ctx)

			localH, ok := handle.(interface {
				ExecuteArgvInSandbox(ctx context.Context, argv []string, env []string) (string, string, int, error)
			})
			if !ok {
				return "", &UBMCPError{
					SchemaVersion:  UBMCPSchemaVersion,
					Tool:           BLPRProducerTool,
					Code:           "AEGISBOX_SANDBOX_VIOLATION",
					ExitCode:       ExitSandboxViolation,
					Retryable:      false,
					Summary:        "Unsupported local sandbox handle.",
					RemediationCmd: "aegisbox doctor",
					Why:            "The local sandbox driver does not expose isolated argv execution.",
				}
			}

			localEnv := make([]string, 0, len(sandboxEnvMap)+len(redeemedLease))
			for k, v := range sandboxEnvMap {
				localEnv = append(localEnv, k+"="+v)
			}
			for _, lease := range redeemedLease {
				entryBuf := make([]byte, 0, len(lease.Key)+1+len(lease.Bytes()))
				entryBuf = append(entryBuf, lease.Key...)
				entryBuf = append(entryBuf, '=')
				entryBuf = append(entryBuf, lease.Bytes()...)
				localEnv = append(localEnv, string(entryBuf))
				clear(entryBuf)
			}
			stdout, stderr, exitCode, _ = localH.ExecuteArgvInSandbox(ctx, []string{"/bin/sh", "-c", cmdVal}, localEnv)
		}

		// 7. Inspect and scrub leased secret bytes from stdout/stderr; fail closed (exit_code: 40) if leaked!
		stdoutBytes := []byte(stdout)
		stderrBytes := []byte(stderr)
		leaked := false
		for _, lease := range redeemedLease {
			sec := lease.Bytes()
			if len(sec) == 0 {
				continue
			}
			trimmed := bytes.TrimSpace(sec)
			if bytes.Contains(stdoutBytes, sec) || bytes.Contains(stderrBytes, sec) ||
				(len(trimmed) >= 4 && (bytes.Contains(stdoutBytes, trimmed) || bytes.Contains(stderrBytes, trimmed))) {
				leaked = true
			}
			stdoutBytes = bytes.ReplaceAll(stdoutBytes, sec, []byte("[REDACTED_SECRET]"))
			stderrBytes = bytes.ReplaceAll(stderrBytes, sec, []byte("[REDACTED_SECRET]"))
			if len(trimmed) >= 4 {
				stdoutBytes = bytes.ReplaceAll(stdoutBytes, trimmed, []byte("[REDACTED_SECRET]"))
				stderrBytes = bytes.ReplaceAll(stderrBytes, trimmed, []byte("[REDACTED_SECRET]"))
			}
		}

		// Zeroize every leased secret byte slice immediately now that execution and inspection completed.
		for _, lease := range redeemedLease {
			lease.Scrub()
		}
		if broker != nil {
			broker.RevokeAll()
		}

		if leaked {
			rcptID := ""
			if !emitSpecified || emitReceipt {
				var rErr error
				rcptID, _, rErr = EmitBLPRReceipt(ctx, ReceiptParams{
					ReceiptDir:     cfg.ReceiptDir,
					SessionID:      sessionID,
					WorkspaceDir:   baseDir,
					SubjectName:    "aegisbox_exec",
					SubjectDigest:  sha256Hex(cmdVal),
					Verdict:        ReceiptVerdictDeny,
					Proven:         true,
					FixForwardCode: "AEGISBOX_SECRET_LEAK_BLOCKED",
					Claims: map[string]interface{}{
						"tool_action":         "aegisbox_exec",
						"vm_backend":          vmBackend,
						"wan_egress":          "deny",
						"secret_leak_blocked": true,
						"leased_secrets_used": len(redeemedLease),
						"proven_findings":     1,
					},
					Signer:       resolveReceiptSigner(cfg),
					ExplicitEmit: emitReceipt,
				})
				if rErr != nil {
					return "", rErr
				}
			}
			return "", &UBMCPError{
				SchemaVersion:  UBMCPSchemaVersion,
				Tool:           BLPRProducerTool,
				Code:           "AEGISBOX_SECRET_LEAK_BLOCKED",
				ExitCode:       ExitSecretGuardBlock,
				Retryable:      true,
				Summary:        "Blocked command output because a leased secret value appeared in stdout or stderr.",
				RemediationCmd: "aegisbox explain secrets",
				Why:            "Opaque Locksmith secrets injected into Aegisbox must never be echoed to stdout or stderr where they could enter LLM context.",
				SelfHeal: &SelfHealSuggestion{
					SuggestedTool: "locksmith_checkout_lease",
					SuggestedArgs: map[string]interface{}{
						"ttl_seconds": 120,
					},
					RequiresHumanApproval: false,
				},
				ReceiptID: rcptID,
			}
		}

		diff, _ := session.CaptureDiff(ctx)

		sanitizer := tui.NewTerminalSanitizer()
		for _, v := range secretsToRedact {
			sanitizer.AddSecretToRedact(v)
		}

		cleanStdout := string(sanitizer.SanitizeBytes(stdoutBytes))
		cleanStderr := string(sanitizer.SanitizeBytes(stderrBytes))

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Exit Code: %d\n", exitCode))
		if cleanStdout != "" {
			sb.WriteString(fmt.Sprintf("Stdout:\n%s\n", cleanStdout))
		}
		if cleanStderr != "" {
			sb.WriteString(fmt.Sprintf("Stderr:\n%s\n", cleanStderr))
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
					return "", &UBMCPError{
						SchemaVersion:  UBMCPSchemaVersion,
						Tool:           BLPRProducerTool,
						Code:           "AEGISBOX_APPLY_BLOCKED",
						ExitCode:       ExitSandboxViolation,
						Retryable:      false,
						Summary:        fmt.Sprintf("Workspace apply blocked by security gate: %s", ux.SanitizeSingleLine(applyErr.Error())),
						RemediationCmd: "aegisbox diff",
						Why:            "Changes containing blocked paths or unvetted patterns are quarantined until reviewed.",
					}
				}
				sb.WriteString("  💾 Changes applied to host workspace.\n")
			}
		}

		if !emitSpecified || emitReceipt {
			verdict := ReceiptVerdictAllow
			if exitCode != 0 {
				verdict = ReceiptVerdictWarn
			}
			if _, _, rErr := EmitBLPRReceipt(ctx, ReceiptParams{
				ReceiptDir:    cfg.ReceiptDir,
				SessionID:     sessionID,
				WorkspaceDir:  baseDir,
				SubjectName:   "aegisbox_exec",
				SubjectDigest: sha256Hex(cmdVal),
				Verdict:       verdict,
				Proven:        exitCode == 0,
				Claims: map[string]interface{}{
					"tool_action":         "aegisbox_exec",
					"vm_backend":          vmBackend,
					"wan_egress":          "deny",
					"exit_code":           exitCode,
					"leased_secrets_used": len(redeemedLease),
					"proven_findings":     0,
				},
				Signer:       resolveReceiptSigner(cfg),
				ExplicitEmit: emitReceipt,
			}); rErr != nil {
				return "", rErr
			}
		}

		return sb.String(), nil

	case "aegisbox_diff":
		if !emitSpecified || emitReceipt {
			if _, _, rErr := EmitBLPRReceipt(ctx, ReceiptParams{
				ReceiptDir:    cfg.ReceiptDir,
				SessionID:     sessionID,
				WorkspaceDir:  workspaceArg,
				SubjectName:   "aegisbox_diff",
				SubjectDigest: sha256Hex("aegisbox_diff:" + workspaceArg),
				Verdict:       ReceiptVerdictAllow,
				Proven:        true,
				Claims: map[string]interface{}{
					"tool_action":     "aegisbox_diff",
					"proven_findings": 0,
				},
				Signer:       resolveReceiptSigner(cfg),
				ExplicitEmit: emitReceipt,
			}); rErr != nil {
				return "", rErr
			}
		}
		return "No active detached session found.", nil

	default:
		return "", &UBMCPError{
			SchemaVersion:  UBMCPSchemaVersion,
			Tool:           BLPRProducerTool,
			Code:           "AEGISBOX_UNKNOWN_TOOL",
			ExitCode:       ExitPolicyDeny,
			Retryable:      false,
			Summary:        fmt.Sprintf("Unknown Aegisbox MCP tool: %s", ux.SanitizeSingleLine(name)),
			RemediationCmd: "aegisbox mcp help",
			Why:            "Only registered tools returned by tools/list may be invoked.",
		}
	}
}

func resolveReceiptSigner(cfg ToolConfig) ReceiptSigner {
	if cfg.ReceiptSigner != nil {
		return cfg.ReceiptSigner
	}
	if cfg.LocksmithBroker != nil {
		return cfg.LocksmithBroker
	}
	return nil
}

func resolveWorkspaceDir(workspaceArg string) (string, error) {
	ws := strings.TrimSpace(workspaceArg)
	if ws == "" {
		return os.Getwd()
	}
	if strings.ContainsRune(ws, '\x00') {
		return "", errors.New("workspace path contains NUL byte")
	}
	clean := filepath.Clean(ws)
	fi, err := os.Stat(clean)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("%s is not a directory", clean)
	}
	return clean, nil
}

func parseOptionalBool(args map[string]interface{}, key string) (bool, bool) {
	raw, exists := args[key]
	if !exists || raw == nil {
		return false, false
	}
	v, ok := raw.(bool)
	return v, ok
}

func parseStringSliceArg(args map[string]interface{}, key string) ([]string, error) {
	raw, exists := args[key]
	if !exists || raw == nil {
		return nil, nil
	}
	switch typed := raw.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" {
				return nil, fmt.Errorf("%s cannot contain empty lease IDs", key)
			}
			out = append(out, trimmed)
		}
		return out, nil
	case []interface{}:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			s, ok := item.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return nil, fmt.Errorf("%s must contain only non-empty strings", key)
			}
			out = append(out, strings.TrimSpace(s))
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s must be an array of strings", key)
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
