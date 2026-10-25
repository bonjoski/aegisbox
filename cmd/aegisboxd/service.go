package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bonjoski/aegisbox/pkg/ipc"
	ipcv1 "github.com/bonjoski/aegisbox/pkg/ipc/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type pendingItem struct {
	req         *ipcv1.InterceptToolCallRequest
	ch          chan string
	timestampNs int64
}

// DaemonServer implements the AegisboxDaemonService gRPC interface.
type DaemonServer struct {
	ipcv1.UnimplementedAegisboxDaemonServiceServer
	supervisor    *Supervisor
	tokens        *ipc.TokenStore
	version       string
	activeProfile string
	mdmLocked     bool
	pending       map[string]*pendingItem // interceptID -> pendingItem
	mu            sync.Mutex
}

// NewDaemonServer initializes the gRPC service handler.
func NewDaemonServer(supervisor *Supervisor, tokens *ipc.TokenStore, version string) *DaemonServer {
	if version == "" {
		version = "v1.0.0"
	}
	return &DaemonServer{
		supervisor:    supervisor,
		tokens:        tokens,
		version:       version,
		activeProfile: "standard",
		mdmLocked:     false,
		pending:       make(map[string]*pendingItem),
	}
}

func (s *DaemonServer) Handshake(ctx context.Context, req *ipcv1.HandshakeRequest) (*ipcv1.HandshakeResponse, error) {
	token, err := s.tokens.IssueToken(req.ClientPid, req.ClientVersion, req.ClientPlatform)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue session token: %v", err)
	}

	return &ipcv1.HandshakeResponse{
		SessionToken:  token,
		DaemonVersion: s.version,
		SupportedFeatures: []string{
			"microvm",
			"mcp-cel",
			"locksmith-secrets",
			"airlock-sandbox",
			"snapshot-pool",
		},
	}, nil
}

func (s *DaemonServer) Heartbeat(ctx context.Context, req *ipcv1.HeartbeatRequest) (*ipcv1.HeartbeatResponse, error) {
	return &ipcv1.HeartbeatResponse{
		ServerTimestampNs: time.Now().UnixNano(),
		IsHealthy:         true,
	}, nil
}

func (s *DaemonServer) StartVM(ctx context.Context, req *ipcv1.StartVMRequest) (*ipcv1.StartVMResponse, error) {
	vm, latencyUs, err := s.supervisor.StartVM(ctx, req)
	if err != nil {
		if errorsIsQuota(err) {
			return nil, status.Error(codes.ResourceExhausted, err.Error())
		}
		return nil, status.Errorf(codes.Internal, "failed to start microVM: %v", err)
	}

	return &ipcv1.StartVMResponse{
		VmId:             vm.ID,
		VsockPort:        vm.VsockPort,
		StartupLatencyUs: latencyUs,
	}, nil
}

func (s *DaemonServer) StopVM(ctx context.Context, req *ipcv1.StopVMRequest) (*ipcv1.StopVMResponse, error) {
	exitCode, err := s.supervisor.StopVM(ctx, req.VmId, req.Force, req.DiscardCowOverlay)
	if err != nil {
		if err == ErrVMNotFound {
			return &ipcv1.StopVMResponse{
				Success:       false,
				ExitCode:      1,
				FailureReason: "microVM not found",
			}, nil
		}
		return &ipcv1.StopVMResponse{
			Success:       false,
			ExitCode:      exitCode,
			FailureReason: err.Error(),
		}, nil
	}

	return &ipcv1.StopVMResponse{
		Success:  true,
		ExitCode: exitCode,
	}, nil
}

func (s *DaemonServer) ListVMs(ctx context.Context, req *ipcv1.ListVMsRequest) (*ipcv1.ListVMsResponse, error) {
	summaries := s.supervisor.ListVMs()
	return &ipcv1.ListVMsResponse{
		Instances: summaries,
	}, nil
}

func (s *DaemonServer) StreamVMConsole(req *ipcv1.StreamVMConsoleRequest, stream ipcv1.AegisboxDaemonService_StreamVMConsoleServer) error {
	vm, err := s.supervisor.GetVM(req.VmId)
	if err != nil {
		return status.Errorf(codes.NotFound, "microVM %s not found", req.VmId)
	}

	// Emit initial connection status chunk
	_ = stream.Send(&ipcv1.VMConsoleChunk{
		Data:        []byte(fmt.Sprintf("[aegisboxd] Console attached to %s\n", vm.ID)),
		IsStderr:    false,
		TimestampNs: time.Now().UnixNano(),
	})

	return nil
}

func (s *DaemonServer) InterceptToolCall(ctx context.Context, req *ipcv1.InterceptToolCallRequest) (*ipcv1.InterceptToolCallResponse, error) {
	ch := make(chan string, 1)
	item := &pendingItem{
		req:         req,
		ch:          ch,
		timestampNs: time.Now().UnixNano(),
	}

	s.mu.Lock()
	s.pending[req.InterceptId] = item
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.pending, req.InterceptId)
		s.mu.Unlock()
	}()

	// Await human decision or context timeout
	select {
	case decision := <-ch:
		return &ipcv1.InterceptToolCallResponse{
			Decision: decision,
			Scope:    "SESSION",
		}, nil
	case <-ctx.Done():
		return &ipcv1.InterceptToolCallResponse{
			Decision: "QUARANTINED",
			Scope:    "ONCE",
		}, nil
	}
}

func (s *DaemonServer) SubmitApprovalDecision(ctx context.Context, req *ipcv1.ApprovalDecisionRequest) (*ipcv1.ApprovalDecisionResponse, error) {
	s.mu.Lock()
	item, exists := s.pending[req.InterceptId]
	s.mu.Unlock()

	if !exists {
		return &ipcv1.ApprovalDecisionResponse{
			Acknowledged: false,
			ErrorMessage: "intercept request expired or already decided",
		}, nil
	}

	select {
	case item.ch <- req.Decision:
		return &ipcv1.ApprovalDecisionResponse{
			Acknowledged: true,
		}, nil
	default:
		return &ipcv1.ApprovalDecisionResponse{
			Acknowledged: false,
			ErrorMessage: "decision channel full",
		}, nil
	}
}

func (s *DaemonServer) ListPendingApprovals(ctx context.Context, req *ipcv1.ListPendingApprovalsRequest) (*ipcv1.ListPendingApprovalsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := make([]*ipcv1.PendingApproval, 0, len(s.pending))
	for id, item := range s.pending {
		res = append(res, &ipcv1.PendingApproval{
			InterceptId:  id,
			VmId:         item.req.VmId,
			ToolName:     item.req.ToolName,
			ToolArgsJson: item.req.ToolArgsJson,
			Severity:     item.req.Severity,
			Reason:       item.req.Reason,
			TimestampNs:  item.timestampNs,
		})
	}

	return &ipcv1.ListPendingApprovalsResponse{
		Approvals: res,
	}, nil
}

func (s *DaemonServer) SetProfile(ctx context.Context, req *ipcv1.SetProfileRequest) (*ipcv1.SetProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.mdmLocked && req.Profile == "permissive" {
		return &ipcv1.SetProfileResponse{
			Success:       false,
			ActiveProfile: s.activeProfile,
			ErrorMessage:  "permissive profile disabled by enterprise MDM/GPO policy",
		}, nil
	}

	switch req.Profile {
	case "permissive", "standard", "microvm-hardened":
		s.activeProfile = req.Profile
		return &ipcv1.SetProfileResponse{
			Success:       true,
			ActiveProfile: s.activeProfile,
		}, nil
	default:
		return &ipcv1.SetProfileResponse{
			Success:       false,
			ActiveProfile: s.activeProfile,
			ErrorMessage:  fmt.Sprintf("unknown security profile %q", req.Profile),
		}, nil
	}
}

func (s *DaemonServer) GetProfile(ctx context.Context, req *ipcv1.GetProfileRequest) (*ipcv1.GetProfileResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return &ipcv1.GetProfileResponse{
		ActiveProfile: s.activeProfile,
		MdmLocked:     s.mdmLocked,
	}, nil
}

func (s *DaemonServer) StreamTelemetry(req *ipcv1.StreamTelemetryRequest, stream ipcv1.AegisboxDaemonService_StreamTelemetryServer) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case t := <-ticker.C:
			frame := &ipcv1.TelemetryFrame{
				TimestampNs:      t.UnixNano(),
				VmId:             "system",
				CpuPercent:       0.5,
				MemoryRssBytes:   28 * 1024 * 1024,
				CanaryTriggered:  false,
			}
			if err := stream.Send(frame); err != nil {
				return err
			}
		}
	}
}

func errorsIsQuota(err error) bool {
	return err == ErrMaxVMQuotaExceeded
}
