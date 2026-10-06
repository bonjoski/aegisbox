package workspace_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bonjoski/aegisbox/pkg/workspace"
)

func TestWorkspaceShadow_MaskingAndDiff(t *testing.T) {
	ctx := context.Background()

	// Create temp directory mimicking workspace
	tempDir, err := os.MkdirTemp("", "aegisbox-test-ws-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a sensitive .env file
	envFile := filepath.Join(tempDir, ".env")
	if err := os.WriteFile(envFile, []byte("SECRET_KEY=supersecret123\n"), 0600); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	sessionsDir, err := os.MkdirTemp("", "aegisbox-sessions-*")
	if err != nil {
		t.Fatalf("failed to create sessions dir: %v", err)
	}
	defer os.RemoveAll(sessionsDir)


	mgr, err := workspace.NewWorkspaceManager(sessionsDir)
	if err != nil {
		t.Fatalf("failed to create workspace manager: %v", err)
	}

	session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir:      tempDir,
		Mode:         workspace.ModeDirect,
		MaskPatterns: []string{".env"},
		SyntheticEnv: map[string]string{
			"API_KEY": "sk-dummy-1234",
		},
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Cleanup(ctx)

	// Verify that .env in shadowDir is masked
	shadowEnv := filepath.Join(session.ShadowDir(), ".env")
	content, err := os.ReadFile(shadowEnv)
	if err != nil {
		t.Fatalf("failed to read shadow .env: %v", err)
	}
	if string(content) == "SECRET_KEY=supersecret123\n" {
		t.Errorf("expected sensitive .env to be masked, but leaked real content")
	}

	// Verify synthetic env
	synthEnv := filepath.Join(session.ShadowDir(), ".env.synthetic")
	synthContent, err := os.ReadFile(synthEnv)
	if err != nil {
		t.Fatalf("failed to read .env.synthetic: %v", err)
	}
	if len(synthContent) == 0 {
		t.Errorf("expected synthetic environment to be populated")
	}
}

func TestWorkspaceShadow_InjectFiles(t *testing.T) {
	ctx := context.Background()

	// Create temp directory mimicking workspace
	tempDir, err := os.MkdirTemp("", "aegisbox-test-inject-ws-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create external files to inject (e.g. custom CLAUDE.md)
	externalDir, err := os.MkdirTemp("", "aegisbox-external-*")
	if err != nil {
		t.Fatalf("failed to create external dir: %v", err)
	}
	defer os.RemoveAll(externalDir)

	claudeFile := filepath.Join(externalDir, "custom-rules.md")
	const claudeContent = "# Custom Claude Instructions\nFollow strict TDD.\n"
	if err := os.WriteFile(claudeFile, []byte(claudeContent), 0644); err != nil {
		t.Fatalf("failed to write custom rules: %v", err)
	}

	subPromptFile := filepath.Join(externalDir, "prompt.txt")
	const promptContent = "SYSTEM PROMPT V1"
	if err := os.WriteFile(subPromptFile, []byte(promptContent), 0644); err != nil {
		t.Fatalf("failed to write sub prompt: %v", err)
	}

	sessionsDir, err := os.MkdirTemp("", "aegisbox-inject-sessions-*")
	if err != nil {
		t.Fatalf("failed to create sessions dir: %v", err)
	}
	defer os.RemoveAll(sessionsDir)

	mgr, err := workspace.NewWorkspaceManager(sessionsDir)
	if err != nil {
		t.Fatalf("failed to create workspace manager: %v", err)
	}

	session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir: tempDir,
		Mode:    workspace.ModeDirect,
		InjectFiles: map[string]string{
			"CLAUDE.md":          claudeFile,
			"prompts/system.txt": subPromptFile,
		},
	})
	if err != nil {
		t.Fatalf("failed to create session with inject files: %v", err)
	}
	defer session.Cleanup(ctx)

	// 1. Verify injected files exist in shadowDir with correct content
	shadowClaude := filepath.Join(session.ShadowDir(), "CLAUDE.md")
	data, err := os.ReadFile(shadowClaude)
	if err != nil {
		t.Fatalf("failed to read injected CLAUDE.md in shadow dir: %v", err)
	}
	if string(data) != claudeContent {
		t.Fatalf("expected injected CLAUDE.md content %q, got: %q", claudeContent, string(data))
	}

	shadowSubPrompt := filepath.Join(session.ShadowDir(), "prompts", "system.txt")
	subData, err := os.ReadFile(shadowSubPrompt)
	if err != nil {
		t.Fatalf("failed to read injected subprompt in shadow dir: %v", err)
	}
	if string(subData) != promptContent {
		t.Fatalf("expected injected subprompt content %q, got: %q", promptContent, string(subData))
	}

	// 2. Verify that injected files DO NOT exist on the host workspace
	hostClaude := filepath.Join(tempDir, "CLAUDE.md")
	if _, err := os.Stat(hostClaude); !os.IsNotExist(err) {
		t.Fatalf("SECURITY VIOLATION: injected file leaked to host base dir before apply: %v", hostClaude)
	}

	// 3. Verify ApplyToHost DOES NOT copy injected files to host
	if err := session.ApplyToHost(ctx); err != nil {
		t.Fatalf("ApplyToHost failed: %v", err)
	}
	if _, err := os.Stat(hostClaude); !os.IsNotExist(err) {
		t.Fatalf("SECURITY VIOLATION: ephemeral injected file was copied to host on ApplyToHost!")
	}
}
