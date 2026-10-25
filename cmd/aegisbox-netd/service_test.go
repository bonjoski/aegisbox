package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bonjoski/aegisbox/pkg/ipc"
	ipcv1 "github.com/bonjoski/aegisbox/pkg/ipc/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func TestValidator_InterfaceName(t *testing.T) {
	valid := []string{"aegis-tap0", "aegis-tap1", "aegis-tap999", "lo0", "dummy0"}
	for _, name := range valid {
		if err := ValidateInterfaceName(name); err != nil {
			t.Errorf("expected valid interface name %q, got error: %v", name, err)
		}
	}

	invalid := []string{
		"eth0",
		"en0",
		"aegis-tap",
		"aegis-tap12345",
		"aegis-tap0; rm -rf /",
		"../../../etc/shadow",
		"",
	}
	for _, name := range invalid {
		if err := ValidateInterfaceName(name); err == nil {
			t.Errorf("expected rejection for malicious/invalid interface name %q, but got nil", name)
		}
	}
}

func TestValidator_IPOrCIDR(t *testing.T) {
	valid := []string{"192.168.1.1", "10.0.0.0/8", "169.254.169.254", "2606:4700:4700::1111"}
	for _, ipStr := range valid {
		if err := ValidateIPOrCIDR(ipStr); err != nil {
			t.Errorf("expected valid IP/CIDR %q, got: %v", ipStr, err)
		}
	}

	invalid := []string{
		"999.999.999.999",
		"10.0.0.1; rm -rf /",
		"http://evil.com",
		"192.168.1.1/33",
		"",
	}
	for _, ipStr := range invalid {
		if err := ValidateIPOrCIDR(ipStr); err == nil {
			t.Errorf("expected rejection for invalid IP %q, but got nil", ipStr)
		}
	}
}

func setupTestNetd(t *testing.T) (ipcv1.AegisboxNetdServiceClient, func()) {
	t.Helper()

	tempDir, err := os.MkdirTemp("/tmp", "agnetd_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	socketPath := filepath.Join(tempDir, "n.sock")
	listener, err := ipc.ListenSecureIPC(socketPath)
	if err != nil {
		_ = os.RemoveAll(tempDir)
		t.Fatalf("failed to listen on test socket: %v", err)
	}

	grpcServer := grpc.NewServer()
	netdServer := NewNetdServer()
	ipcv1.RegisterAegisboxNetdServiceServer(grpcServer, netdServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return ipc.DialSecureIPC(ctx, socketPath)
	}

	conn, err := grpc.DialContext(context.Background(), "passthrough:///netd",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		grpcServer.Stop()
		_ = listener.Close()
		_ = os.RemoveAll(tempDir)
		t.Fatalf("failed to dial test netd: %v", err)
	}

	client := ipcv1.NewAegisboxNetdServiceClient(conn)

	cleanup := func() {
		_ = conn.Close()
		grpcServer.GracefulStop()
		_ = listener.Close()
		_ = os.RemoveAll(tempDir)
	}

	return client, cleanup
}

func TestNetdServer_EndToEnd(t *testing.T) {
	client, cleanup := setupTestNetd(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Allocate TAP successfully
	allocResp, err := client.AllocateTap(ctx, &ipcv1.AllocateTapRequest{
		TargetUid:      uint32(os.Getuid()),
		RequestedName: "aegis-tap42",
	})
	if err != nil {
		t.Fatalf("AllocateTap failed: %v", err)
	}
	if allocResp.InterfaceName != "aegis-tap42" {
		t.Errorf("expected interface name 'aegis-tap42', got %q", allocResp.InterfaceName)
	}

	// 2. Reject Duplicate Allocation
	_, err = client.AllocateTap(ctx, &ipcv1.AllocateTapRequest{
		RequestedName: "aegis-tap42",
	})
	if err == nil {
		t.Fatalf("expected duplicate TAP allocation to fail")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.AlreadyExists {
		t.Errorf("expected codes.AlreadyExists, got: %v", err)
	}

	// 3. Reject Malicious Interface Name Injection
	_, err = client.AllocateTap(ctx, &ipcv1.AllocateTapRequest{
		RequestedName: "eth0; rm -rf /",
	})
	if err == nil {
		t.Fatalf("expected malicious interface name to be rejected")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("expected codes.InvalidArgument, got: %v", err)
	}

	// 4. Apply Valid Firewall Rules
	applyResp, err := client.ApplyFirewallRules(ctx, &ipcv1.ApplyFirewallRulesRequest{
		InterfaceName:     "aegis-tap42",
		AllowedEgressIps:  []string{"140.82.121.4", "104.16.0.0/12"},
		CanarySinkholeIps: []string{"169.254.169.254"},
	})
	if err != nil {
		t.Fatalf("ApplyFirewallRules failed: %v", err)
	}
	if !applyResp.Success || applyResp.AnchorId == "" {
		t.Fatalf("expected successful rule application with non-empty anchor ID")
	}

	// 5. Reject IP Injection Attack
	_, err = client.ApplyFirewallRules(ctx, &ipcv1.ApplyFirewallRulesRequest{
		InterfaceName:    "aegis-tap42",
		AllowedEgressIps: []string{"1.1.1.1; touch /tmp/pwned"},
	})
	if err == nil {
		t.Fatalf("expected invalid IP injection to be rejected")
	}
	if st, ok := status.FromError(err); !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("expected codes.InvalidArgument, got: %v", err)
	}

	// 6. Clear Firewall Rules
	clearResp, err := client.ClearFirewallRules(ctx, &ipcv1.ClearFirewallRulesRequest{
		AnchorId:      applyResp.AnchorId,
		InterfaceName: "aegis-tap42",
	})
	if err != nil || !clearResp.Success {
		t.Fatalf("ClearFirewallRules failed: %v", err)
	}

	// 7. Release TAP
	relResp, err := client.ReleaseTap(ctx, &ipcv1.ReleaseTapRequest{
		InterfaceName: "aegis-tap42",
	})
	if err != nil || !relResp.Success {
		t.Fatalf("ReleaseTap failed: %v", err)
	}
}
