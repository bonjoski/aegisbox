package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bonjoski/aegisbox/pkg/ipc"
	ipcv1 "github.com/bonjoski/aegisbox/pkg/ipc/v1"
	"github.com/bonjoski/aegisbox/pkg/vmm"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func setupTestDaemon(t *testing.T, maxQuota int) (string, *ipc.Client, func()) {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "agdtest_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	socketPath := filepath.Join(tempDir, "d.sock")
	listener, err := ipc.ListenSecureIPC(socketPath)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		t.Fatalf("failed to bind test listener: %v", err)
	}

	driver := vmm.NewLocalProcessDriver()
	supervisor := NewSupervisor(driver, maxQuota, 1)
	tokenStore := ipc.NewTokenStore(1 * time.Hour)
	server := ipc.NewServer(tokenStore)
	daemonService := NewDaemonServer(supervisor, tokenStore, "v1.0.0-test")
	server.RegisterDaemonService(daemonService)

	go func() {
		_ = server.Serve(listener)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := ipc.NewClient(ctx, socketPath)
	if err != nil {
		server.Stop()
		_ = listener.Close()
		_ = os.RemoveAll(tempDir)
		t.Fatalf("failed to create test client: %v", err)
	}

	_, err = client.Authenticate(ctx, "test-client")
	if err != nil {
		_ = client.Close()
		server.Stop()
		_ = listener.Close()
		_ = os.RemoveAll(tempDir)
		t.Fatalf("failed to authenticate client: %v", err)
	}

	cleanup := func() {
		_ = client.Close()
		server.GracefulStop()
		supervisor.TeardownAll(context.Background())
		_ = listener.Close()
		_ = os.RemoveAll(tempDir)
	}

	return socketPath, client, cleanup
}

func TestDaemonServer_StartAndStopVM(t *testing.T) {
	_, client, cleanup := setupTestDaemon(t, 3)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Start VM
	startResp, err := client.StartVM(ctx, &ipcv1.StartVMRequest{
		Profile:       "microvm-hardened",
		WorkspacePath: t.TempDir(),
		VcpuCount:     2,
		MemoryMb:      512,
	})
	if err != nil {
		t.Fatalf("client.StartVM failed: %v", err)
	}
	if startResp.VmId == "" {
		t.Fatalf("expected non-empty VM ID")
	}

	// 2. List VMs
	listResp, err := client.ListVMs(ctx)
	if err != nil {
		t.Fatalf("client.ListVMs failed: %v", err)
	}
	if len(listResp.Instances) != 1 {
		t.Fatalf("expected 1 active VM instance, got %d", len(listResp.Instances))
	}
	if listResp.Instances[0].VmId != startResp.VmId {
		t.Errorf("expected VM ID %s, got %s", startResp.VmId, listResp.Instances[0].VmId)
	}
	if listResp.Instances[0].Status != "running" {
		t.Errorf("expected status 'running', got %s", listResp.Instances[0].Status)
	}

	// 3. Stop VM
	stopResp, err := client.StopVM(ctx, &ipcv1.StopVMRequest{
		VmId:               startResp.VmId,
		DiscardCowOverlay: true,
	})
	if err != nil {
		t.Fatalf("client.StopVM failed: %v", err)
	}
	if !stopResp.Success {
		t.Errorf("expected stop success, got error: %s", stopResp.FailureReason)
	}

	// 4. Verify List is now 0
	listAfter, err := client.ListVMs(ctx)
	if err != nil {
		t.Fatalf("client.ListVMs failed after stop: %v", err)
	}
	if len(listAfter.Instances) != 0 {
		t.Errorf("expected 0 instances after stop, got %d", len(listAfter.Instances))
	}
}

func TestDaemonServer_QuotaEnforcement(t *testing.T) {
	_, client, cleanup := setupTestDaemon(t, 2) // Limit: 2 VMs
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// VM 1
	vm1, err := client.StartVM(ctx, &ipcv1.StartVMRequest{
		Profile:       "standard",
		WorkspacePath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("failed to start VM 1: %v", err)
	}

	// VM 2
	vm2, err := client.StartVM(ctx, &ipcv1.StartVMRequest{
		Profile:       "standard",
		WorkspacePath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("failed to start VM 2: %v", err)
	}

	// VM 3 (should fail due to quota)
	_, err = client.StartVM(ctx, &ipcv1.StartVMRequest{
		Profile:       "standard",
		WorkspacePath: t.TempDir(),
	})
	if err == nil {
		t.Fatalf("expected VM 3 to fail due to quota, but succeeded")
	}

	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.ResourceExhausted {
		t.Errorf("expected codes.ResourceExhausted, got: %v", err)
	}

	// Cleanup VM 1
	_, _ = client.StopVM(ctx, &ipcv1.StopVMRequest{VmId: vm1.VmId})
	_, _ = client.StopVM(ctx, &ipcv1.StopVMRequest{VmId: vm2.VmId})
}

func TestDaemonServer_InterceptAndApproval(t *testing.T) {
	_, client, cleanup := setupTestDaemon(t, 3)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	interceptID := "int-12345"
	interceptResultChan := make(chan string, 1)

	// 1. In goroutine, simulate tool call intercept waiting for approval
	go func() {
		resp, err := client.InterceptToolCall(ctx, &ipcv1.InterceptToolCallRequest{
			InterceptId:  interceptID,
			VmId:         "vm-1",
			ToolName:     "run_command",
			ToolArgsJson: `{"command": "curl http://evil.com"}`,
			Severity:     "HIGH",
			Reason:       "unapproved external domain",
		})
		if err != nil {
			interceptResultChan <- "INTERCEPT_ERR: " + err.Error()
			return
		}
		interceptResultChan <- resp.Decision
	}()

	// 2. Allow handler registration
	time.Sleep(50 * time.Millisecond)

	// 3. Human submits approval decision
	resp, err := client.SubmitApprovalDecision(ctx, interceptID, "APPROVED", "SESSION")
	if err != nil {
		t.Fatalf("SubmitApprovalDecision failed: %v", err)
	}
	if !resp.Acknowledged {
		t.Fatalf("expected decision to be acknowledged")
	}

	// 4. Verify intercept unblocks with APPROVED
	select {
	case decision := <-interceptResultChan:
		if decision != "APPROVED" {
			t.Errorf("expected decision 'APPROVED', got %s", decision)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for intercept resolution")
	}
}
