package mcp

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/argus"
	"github.com/bonjoski/aegisbox/pkg/vmm"
	"github.com/bonjoski/aegisbox/pkg/workspace"
)

// MCPTool defines the schema for an MCP exposed tool.
type MCPTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
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
				"type": "object",
			},
		},
	}
}

// HandleToolCall executes the corresponding Aegisbox engine logic for a tool call.
func HandleToolCall(ctx context.Context, name string, args map[string]interface{}) (string, error) {
	switch name {
	case "aegisbox_vet":
		cmdVal, ok := args["command"].(string)
		if !ok || cmdVal == "" {
			return "", fmt.Errorf("missing required 'command' argument")
		}

		analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict)
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

		// Pre-flight check
		analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict)
		report, err := analyzer.Analyze(ctx, cmdVal)
		if err != nil {
			return "", fmt.Errorf("pre-flight check failed: %w", err)
		}
		if !report.Allowed {
			return "", fmt.Errorf("command blocked by Aegisbox security policy: %s", report.Findings[0].Description)
		}

		// Workspace setup
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

		driver := vmm.NewLocalProcessDriver()
		handle, err := driver.SpawnVM(ctx, vmm.VMConfig{
			ID:             session.ID(),
			WorkspaceMount: session.ShadowDir(),
		})
		if err != nil {
			return "", fmt.Errorf("sandbox spawn error: %w", err)
		}

		localH := handle.(interface {
			ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error)
		})

		stdout, stderr, exitCode, _ := localH.ExecuteInSandbox(ctx, cmdVal, nil)
		diff, _ := session.CaptureDiff(ctx)

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Exit Code: %d\n", exitCode))
		if stdout != "" {
			sb.WriteString(fmt.Sprintf("Stdout:\n%s\n", stdout))
		}
		if stderr != "" {
			sb.WriteString(fmt.Sprintf("Stderr:\n%s\n", stderr))
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
				_ = session.ApplyToHost(ctx)
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
