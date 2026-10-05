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
