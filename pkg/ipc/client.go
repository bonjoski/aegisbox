package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	ipcv1 "github.com/bonjoski/aegisbox/pkg/ipc/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// Client wraps the gRPC client for interacting with the aegisboxd service.
type Client struct {
	conn         *grpc.ClientConn
	daemonClient ipcv1.AegisboxDaemonServiceClient
	sessionToken string
	mu           sync.RWMutex
}

// NewClient initializes a client and connects to the local aegisboxd IPC endpoint.
func NewClient(ctx context.Context, socketPath string) (*Client, error) {
	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		return DialSecureIPC(ctx, socketPath)
	}

	conn, err := grpc.DialContext(ctx, "passthrough:///aegisboxd",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial aegisboxd socket: %w", err)
	}

	c := &Client{
		conn:         conn,
		daemonClient: ipcv1.NewAegisboxDaemonServiceClient(conn),
	}

	return c, nil
}

// Authenticate performs the initial handshake and obtains an ephemeral session token.
func (c *Client) Authenticate(ctx context.Context, clientVersion string) (*ipcv1.HandshakeResponse, error) {
	req := &ipcv1.HandshakeRequest{
		ClientVersion:  clientVersion,
		ClientPid:      uint32(os.Getpid()),
		ClientPlatform: runtime.GOOS,
	}

	resp, err := c.daemonClient.Handshake(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("daemon handshake failed: %w", err)
	}

	c.mu.Lock()
	c.sessionToken = resp.SessionToken
	c.mu.Unlock()

	return resp, nil
}

func (c *Client) withAuth(ctx context.Context) context.Context {
	c.mu.RLock()
	token := c.sessionToken
	c.mu.RUnlock()

	if token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "x-aegisbox-session-token", token)
}

// StartVM requests the daemon to provision and launch a microVM instance.
func (c *Client) StartVM(ctx context.Context, req *ipcv1.StartVMRequest) (*ipcv1.StartVMResponse, error) {
	return c.daemonClient.StartVM(c.withAuth(ctx), req)
}

// StopVM terminates a running microVM instance.
func (c *Client) StopVM(ctx context.Context, req *ipcv1.StopVMRequest) (*ipcv1.StopVMResponse, error) {
	return c.daemonClient.StopVM(c.withAuth(ctx), req)
}

// ListVMs lists all active microVM instances managed by the daemon.
func (c *Client) ListVMs(ctx context.Context) (*ipcv1.ListVMsResponse, error) {
	c.mu.RLock()
	token := c.sessionToken
	c.mu.RUnlock()

	return c.daemonClient.ListVMs(c.withAuth(ctx), &ipcv1.ListVMsRequest{
		SessionToken: token,
	})
}

// InterceptToolCall submits a tool call to the daemon for policy evaluation.
func (c *Client) InterceptToolCall(ctx context.Context, req *ipcv1.InterceptToolCallRequest) (*ipcv1.InterceptToolCallResponse, error) {
	return c.daemonClient.InterceptToolCall(c.withAuth(ctx), req)
}

// SubmitApprovalDecision conveys a human-in-the-loop decision back to the daemon.
func (c *Client) SubmitApprovalDecision(ctx context.Context, interceptID, decision, scope string) (*ipcv1.ApprovalDecisionResponse, error) {
	c.mu.RLock()
	token := c.sessionToken
	c.mu.RUnlock()

	req := &ipcv1.ApprovalDecisionRequest{
		SessionToken: token,
		InterceptId:  interceptID,
		Decision:     decision,
		Scope:        scope,
	}
	return c.daemonClient.SubmitApprovalDecision(c.withAuth(ctx), req)
}

// StreamTelemetry establishes a streaming subscription to live daemon telemetry.
func (c *Client) StreamTelemetry(ctx context.Context, includeNetwork bool) (ipcv1.AegisboxDaemonService_StreamTelemetryClient, error) {
	c.mu.RLock()
	token := c.sessionToken
	c.mu.RUnlock()

	req := &ipcv1.StreamTelemetryRequest{
		SessionToken:          token,
		IncludeNetworkEgress: includeNetwork,
	}
	return c.daemonClient.StreamTelemetry(c.withAuth(ctx), req)
}

// Heartbeat verifies daemon liveness.
func (c *Client) Heartbeat(ctx context.Context) (*ipcv1.HeartbeatResponse, error) {
	c.mu.RLock()
	token := c.sessionToken
	c.mu.RUnlock()

	req := &ipcv1.HeartbeatRequest{
		SessionToken:      token,
		ClientTimestampNs: time.Now().UnixNano(),
	}
	return c.daemonClient.Heartbeat(c.withAuth(ctx), req)
}

// ListPendingApprovals retrieves pending human-in-the-loop approval requests.
func (c *Client) ListPendingApprovals(ctx context.Context) (*ipcv1.ListPendingApprovalsResponse, error) {
	c.mu.RLock()
	token := c.sessionToken
	c.mu.RUnlock()

	return c.daemonClient.ListPendingApprovals(c.withAuth(ctx), &ipcv1.ListPendingApprovalsRequest{
		SessionToken: token,
	})
}

// SetProfile updates the active security posture profile.
func (c *Client) SetProfile(ctx context.Context, profile string) (*ipcv1.SetProfileResponse, error) {
	c.mu.RLock()
	token := c.sessionToken
	c.mu.RUnlock()

	return c.daemonClient.SetProfile(c.withAuth(ctx), &ipcv1.SetProfileRequest{
		SessionToken: token,
		Profile:      profile,
	})
}

// GetProfile retrieves the active security profile and enterprise lock status.
func (c *Client) GetProfile(ctx context.Context) (*ipcv1.GetProfileResponse, error) {
	c.mu.RLock()
	token := c.sessionToken
	c.mu.RUnlock()

	return c.daemonClient.GetProfile(c.withAuth(ctx), &ipcv1.GetProfileRequest{
		SessionToken: token,
	})
}

// SessionToken returns the authenticated session token.
func (c *Client) SessionToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionToken
}

// Close closes the underlying gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
