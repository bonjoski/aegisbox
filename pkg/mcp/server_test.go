package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/aegisbox/pkg/mcp"
	"github.com/bonjoski/aegisbox/pkg/vmm"
)

func TestMCPServer_InitializeAndListTools(t *testing.T) {
	ctx := context.Background()

	// 1. Initialize Request
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	// 2. Initialized Notification (MCP spec: notification has no ID and must NOT receive a response)
	notifReq := `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
	// 3. Tools List Request
	listReq := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n"

	in := strings.NewReader(initReq + notifReq + listReq)
	var out bytes.Buffer

	server := mcp.NewMCPServer(in, &out)
	if err := server.Serve(ctx); err != nil {
		t.Fatalf("MCP serve failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	// Exactly 2 responses expected: for ID 1 and ID 2 (notification must produce NO output)
	if len(lines) != 2 {
		t.Fatalf("expected exactly 2 responses (no reply to notification), got %d: %v", len(lines), lines)
	}

	var initResp mcp.JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatalf("failed to unmarshal init response: %v", err)
	}
	if initResp.Error != nil {
		t.Errorf("unexpected error in init response: %+v", initResp.Error)
	}

	var listResp mcp.JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatalf("failed to unmarshal list response: %v", err)
	}
	if listResp.Error != nil {
		t.Errorf("unexpected error in list response: %+v", listResp.Error)
	}
	if listResp.ID != float64(2) && listResp.ID != 2 {
		t.Errorf("expected list response ID to be 2, got %v", listResp.ID)
	}
}

func TestMCPServer_ToolCallVet(t *testing.T) {
	ctx := context.Background()

	res, err := mcp.HandleToolCall(ctx, "aegisbox_vet", map[string]interface{}{
		"command": "go test ./...",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(res, "Pre-Flight Gate PASSED") {
		t.Errorf("expected clean command to pass vet, got: %s", res)
	}
}

func TestMCPServer_ToolCallExecFailsClosedWithoutHypervisor(t *testing.T) {
	ctx := context.Background()
	if err := vmm.NewPlatformDriver().VerifyPrerequisites(ctx); err == nil {
		t.Skip("hardware hypervisor is provisioned on this host")
	}

	_, err := mcp.HandleToolCall(ctx, "aegisbox_exec", map[string]interface{}{
		"command": "echo hello",
	})
	if err == nil {
		t.Fatalf("expected HandleToolCall without AllowDegradedLocal to fail closed when hypervisor is unavailable")
	}
}

func TestMCPServer_ToolCallExecWithEnvForwarding(t *testing.T) {
	ctx := context.Background()

	t.Setenv("AEGISBOX_ALLOW_ENV", "AGENT_API_KEY")
	t.Setenv("AGENT_API_KEY", "my-super-secret-key-mcp")

	res, err := mcp.HandleToolCallWithConfig(ctx, "aegisbox_exec", map[string]interface{}{
		"command": "echo SECRET=$AGENT_API_KEY",
	}, mcp.ToolConfig{AllowDegradedLocal: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(res, "my-super-secret-key-mcp") {
		t.Errorf("critical leak: secret was not redacted from MCP response: %s", res)
	}
	if !strings.Contains(res, "[REDACTED_SECRET]") {
		t.Errorf("expected [REDACTED_SECRET] in output: %s", res)
	}
}

func TestAegisbox_OpaqueLeaseNoSubprocessAndZeroize(t *testing.T) {
	ctx := context.Background()

	// 1. Verify pkg/mcp/locksmith.go has ZERO os/exec imports or exec.Command calls (NFR-LEASE-04)
	locksmithSrc, err := os.ReadFile("locksmith.go")
	if err != nil {
		t.Fatalf("read locksmith.go: %v", err)
	}
	srcStr := string(locksmithSrc)
	if strings.Contains(srcStr, `"os/exec"`) || strings.Contains(srcStr, "exec.Command") {
		t.Fatalf("NFR-LEASE-04 violation: pkg/mcp/locksmith.go must not import os/exec or spawn subprocesses")
	}

	// Also plant a canary "locksmith" executable in PATH that records if anything ever spawns it.
	poisonDir := t.TempDir()
	markerFile := filepath.Join(poisonDir, "subprocess_spawned")
	poisonBin := filepath.Join(poisonDir, "locksmith")
	poisonScript := "#!/bin/sh\necho spawned > " + markerFile + "\nexit 99\n"
	if err := os.WriteFile(poisonBin, []byte(poisonScript), 0o700); err != nil {
		t.Fatalf("write poison locksmith binary: %v", err)
	}
	t.Setenv("PATH", poisonDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// 2. Start mock Locksmith UDS server with an opaque lease
	const (
		leaseID   = "lease_01JCANARYLEASE01"
		sessionID = "sess_01JOPAQUETEST01"
		canaryVal = "sk-live-canary-zeroize-secret-7744"
	)
	daemon := startMockLocksmithDaemon(t, map[string]mockLeaseEntry{
		leaseID: {
			SessionID: sessionID,
			EnvVar:    "CANARY_API_KEY",
			Secret:    []byte(canaryVal),
		},
	})
	t.Setenv("LOCKSMITH_SOCKET", daemon.sockPath)

	// 3. Direct UDS redemption + deterministic byte-slice zeroization check
	broker, err := mcp.NewLocksmithBroker()
	if err != nil {
		t.Fatalf("NewLocksmithBroker failed: %v", err)
	}
	lease, err := broker.RedeemOpaqueLease(ctx, leaseID, sessionID)
	if err != nil {
		t.Fatalf("RedeemOpaqueLease failed: %v", err)
	}
	if lease.Key != "CANARY_API_KEY" {
		t.Fatalf("expected lease.Key='CANARY_API_KEY', got %q", lease.Key)
	}
	if !bytes.Equal(lease.Bytes(), []byte(canaryVal)) {
		t.Fatalf("unexpected secret bytes redeemed from UDS")
	}

	// Verify exact UDS wire fields sent to Locksmith
	daemon.mu.Lock()
	if len(daemon.requests) != 1 {
		daemon.mu.Unlock()
		t.Fatalf("expected 1 UDS request, got %d", len(daemon.requests))
	}
	wireReq := daemon.requests[0]
	daemon.mu.Unlock()
	if wireReq["version"] != "1.0" || wireReq["action"] != "redeem_opaque_lease" || wireReq["lease_id"] != leaseID || wireReq["session_id"] != sessionID {
		t.Fatalf("unexpected UDS redeem request payload: %#v", wireReq)
	}
	if pid, _ := wireReq["client_pid"].(float64); pid <= 0 {
		t.Errorf("expected positive client_pid, got %v", wireReq["client_pid"])
	}
	if startTime, _ := wireReq["process_start_time"].(float64); startTime <= 0 {
		t.Errorf("expected positive process_start_time, got %v", wireReq["process_start_time"])
	}

	// Hold reference to the underlying backing array and verify RevokeAll() zeroes every byte
	backingRef := lease.Bytes()
	broker.RevokeAll()
	if lease.Bytes() != nil {
		t.Fatalf("expected lease.Bytes() == nil after RevokeAll()")
	}
	for i, b := range backingRef {
		if b != 0 {
			t.Fatalf("memory zeroization failed at byte %d: got 0x%02x (expected 0x00)", i, b)
		}
	}

	// Also verify direct Scrub() zeroizes backing slice
	lease2, err := broker.RedeemOpaqueLease(ctx, leaseID, sessionID)
	if err != nil {
		t.Fatalf("second RedeemOpaqueLease failed: %v", err)
	}
	backingRef2 := lease2.Bytes()
	lease2.Scrub()
	for i, b := range backingRef2 {
		if b != 0 {
			t.Fatalf("Scrub() zeroization failed at byte %d: got 0x%02x", i, b)
		}
	}

	// 4. End-to-end aegisbox_exec via MCPServer: leaked secret MUST be scrubbed and fail closed with exit_code 40
	receiptDir := t.TempDir()
	wsDir := t.TempDir()

	leakReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      401,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "aegisbox_exec",
			"arguments": map[string]interface{}{
				"command":       "echo LEAKED=$CANARY_API_KEY",
				"workspace":     wsDir,
				"session_id":    sessionID,
				"secret_leases": []string{leaseID},
				"emit_receipt":  true,
			},
		},
	}
	// Non-leaking command using the leased secret MUST succeed
	safeReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      402,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "aegisbox_exec",
			"arguments": map[string]interface{}{
				"command":       `test -n "$CANARY_API_KEY" && echo LEASE_ACTIVE_OK`,
				"workspace":     wsDir,
				"session_id":    sessionID,
				"secret_leases": []string{leaseID},
				"emit_receipt":  true,
			},
		},
	}

	b1, _ := json.Marshal(leakReq)
	b2, _ := json.Marshal(safeReq)
	var mcpOut bytes.Buffer
	srv := mcp.NewMCPServerWithOptions(
		bytes.NewReader(append(append(b1, '\n'), append(b2, '\n')...)),
		&mcpOut,
		mcp.ServerOptions{
			AllowDegradedLocal: true,
			LocksmithBroker:    mcp.NewLocksmithBrokerWithSocket(daemon.sockPath),
			ReceiptDir:         receiptDir,
		},
	)
	if err := srv.Serve(ctx); err != nil {
		t.Fatalf("MCP server Serve failed: %v", err)
	}

	rawOut := mcpOut.String()
	if strings.Contains(rawOut, canaryVal) {
		t.Fatalf("CRITICAL LEAK: leased canary secret bytes appeared in MCP JSON-RPC response: %s", rawOut)
	}

	lines := strings.Split(strings.TrimSpace(rawOut), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 MCP responses, got %d: %s", len(lines), rawOut)
	}

	var leakResp, safeResp mcp.JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[0]), &leakResp); err != nil {
		t.Fatalf("unmarshal leakResp: %v", err)
	}
	assertUBMCPErrorConformance(t, leakResp.Result.(map[string]interface{}), mcp.ExitSecretGuardBlock, "AEGISBOX_SECRET_LEAK_BLOCKED")

	if err := json.Unmarshal([]byte(lines[1]), &safeResp); err != nil {
		t.Fatalf("unmarshal safeResp: %v", err)
	}
	safeRes := safeResp.Result.(map[string]interface{})
	if isErr, _ := safeRes["isError"].(bool); isErr {
		t.Fatalf("expected non-leaking command with secret_leases to succeed, got error: %#v", safeRes)
	}
	safeContent := safeRes["content"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if !strings.Contains(safeContent, "LEASE_ACTIVE_OK") {
		t.Errorf("expected LEASE_ACTIVE_OK in stdout, got: %s", safeContent)
	}

	// Verify 2 signed BLPR-v1 receipts were emitted (1 deny + 1 allow) and ZERO contain the canary secret
	entries, err := os.ReadDir(receiptDir)
	if err != nil {
		t.Fatalf("read receiptDir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 signed BLPR-v1 receipts, got %d", len(entries))
	}
	for _, entry := range entries {
		data, rErr := os.ReadFile(filepath.Join(receiptDir, entry.Name()))
		if rErr != nil {
			t.Fatalf("read receipt %s: %v", entry.Name(), rErr)
		}
		if strings.Contains(string(data), canaryVal) {
			t.Fatalf("CRITICAL LEAK: canary secret appeared in BLPR-v1 receipt %s", entry.Name())
		}
		var env mcp.DSSEEnvelope
		if uErr := json.Unmarshal(data, &env); uErr != nil {
			t.Fatalf("unmarshal receipt %s: %v", entry.Name(), uErr)
		}
		if _, vErr := mcp.VerifyReceiptEnvelope(&env, daemon.pub); vErr != nil {
			t.Fatalf("VerifyReceiptEnvelope failed for %s: %v", entry.Name(), vErr)
		}
	}

	// Confirm the poisoned locksmith subprocess binary was NEVER executed
	if _, statErr := os.Stat(markerFile); statErr == nil {
		t.Fatalf("NFR-LEASE-04 violation: locksmith CLI subprocess was spawned!")
	}
}
