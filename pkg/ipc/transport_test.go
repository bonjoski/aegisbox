package ipc

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	ipcv1 "github.com/bonjoski/aegisbox/pkg/ipc/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockDaemonServer implements ipcv1.AegisboxDaemonServiceServer for testing.
type mockDaemonServer struct {
	ipcv1.UnimplementedAegisboxDaemonServiceServer
	tokens *TokenStore
}

func (m *mockDaemonServer) Handshake(ctx context.Context, req *ipcv1.HandshakeRequest) (*ipcv1.HandshakeResponse, error) {
	token, err := m.tokens.IssueToken(req.ClientPid, req.ClientVersion, req.ClientPlatform)
	if err != nil {
		return nil, err
	}
	return &ipcv1.HandshakeResponse{
		SessionToken:       token,
		DaemonVersion:      "v1.0.0-test",
		SupportedFeatures: []string{"microvm", "mcp-cel", "spiffe"},
	}, nil
}

func (m *mockDaemonServer) Heartbeat(ctx context.Context, req *ipcv1.HeartbeatRequest) (*ipcv1.HeartbeatResponse, error) {
	return &ipcv1.HeartbeatResponse{
		ServerTimestampNs: time.Now().UnixNano(),
		IsHealthy:         true,
	}, nil
}

func TestSecureIPC_SymlinkRejection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping unix domain socket test on windows")
	}

	tempDir, err := os.MkdirTemp("", "agsym_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	realDir := filepath.Join(tempDir, "real")
	if err := os.Mkdir(realDir, 0700); err != nil {
		t.Fatalf("failed to create real dir: %v", err)
	}

	symlinkDir := filepath.Join(tempDir, "sym_dir")
	if err := os.Symlink(realDir, symlinkDir); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	targetSocket := filepath.Join(symlinkDir, "t.sock")
	_, err = ListenSecureIPC(targetSocket)
	if err == nil {
		t.Fatalf("expected ListenSecureIPC to reject symlink parent directory, but got nil")
	}

	if !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("expected error message to mention symbolic link, got: %v", err)
	}
}

func TestSecureIPC_EndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping unix domain socket test on windows")
	}

	tempDir, err := os.MkdirTemp("", "agtest_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "test.sock")

	listener, err := ListenSecureIPC(socketPath)
	if err != nil {
		t.Fatalf("ListenSecureIPC failed: %v", err)
	}
	defer listener.Close()

	// Verify socket file permissions are 0600
	fi, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatalf("failed to stat socket: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Errorf("expected socket permissions 0600, got %v", fi.Mode().Perm())
	}

	tokens := NewTokenStore(1 * time.Hour)
	server := NewServer(tokens)
	server.RegisterDaemonService(&mockDaemonServer{tokens: tokens})

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(listener)
	}()
	defer server.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	client, err := NewClient(ctx, socketPath)
	if err != nil {
		t.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	// Step 1: Call Heartbeat without authentication -> Must be rejected with Unauthenticated
	_, err = client.Heartbeat(ctx)
	if err == nil {
		t.Fatalf("expected unauthenticated heartbeat to fail")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unauthenticated {
		t.Errorf("expected codes.Unauthenticated, got: %v", err)
	}

	// Step 2: Handshake
	resp, err := client.Authenticate(ctx, "v1.0.0")
	if err != nil {
		t.Fatalf("client.Authenticate failed: %v", err)
	}
	if resp.SessionToken == "" {
		t.Fatalf("received empty session token")
	}

	// Step 3: Call Heartbeat with authentication -> Must succeed
	hb, err := client.Heartbeat(ctx)
	if err != nil {
		t.Fatalf("authenticated heartbeat failed: %v", err)
	}
	if !hb.IsHealthy {
		t.Errorf("expected healthy daemon response")
	}
}

func BenchmarkIPCRoundtrip(b *testing.B) {
	if runtime.GOOS == "windows" {
		b.Skip("skipping unix domain socket benchmark on windows")
	}

	tempDir, err := os.MkdirTemp("", "agbench_*")
	if err != nil {
		b.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	socketPath := filepath.Join(tempDir, "b.sock")

	listener, err := ListenSecureIPC(socketPath)
	if err != nil {
		b.Fatalf("ListenSecureIPC failed: %v", err)
	}
	defer listener.Close()

	tokens := NewTokenStore(1 * time.Hour)
	server := NewServer(tokens)
	server.RegisterDaemonService(&mockDaemonServer{tokens: tokens})

	go func() {
		_ = server.Serve(listener)
	}()
	defer server.GracefulStop()

	ctx := context.Background()
	client, err := NewClient(ctx, socketPath)
	if err != nil {
		b.Fatalf("NewClient failed: %v", err)
	}
	defer client.Close()

	if _, err := client.Authenticate(ctx, "bench"); err != nil {
		b.Fatalf("Authenticate failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hb, err := client.Heartbeat(ctx)
		if err != nil || !hb.IsHealthy {
			b.Fatalf("Heartbeat failed: %v", err)
		}
	}
}
