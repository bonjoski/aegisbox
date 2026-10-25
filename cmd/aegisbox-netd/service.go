package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	ipcv1 "github.com/bonjoski/aegisbox/pkg/ipc/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NetdServer implements the AegisboxNetdService gRPC interface.
type NetdServer struct {
	ipcv1.UnimplementedAegisboxNetdServiceServer
	allocatedTaps map[string]*TapInfo
	activeAnchors map[string]*FirewallAnchor
	counter       uint64
	mu            sync.Mutex
}

// TapInfo tracks an active allocated TAP device.
type TapInfo struct {
	InterfaceName string
	SubnetCIDR    string
	GatewayIP     string
	GuestIP       string
	TargetUID     uint32
	TargetGID     uint32
}

// FirewallAnchor tracks an active firewall ruleset anchor.
type FirewallAnchor struct {
	AnchorID       string
	InterfaceName  string
	AllowedEgress  []string
	CanarySinkhole []string
}

// NewNetdServer initializes the privileged helper server.
func NewNetdServer() *NetdServer {
	return &NetdServer{
		allocatedTaps: make(map[string]*TapInfo),
		activeAnchors: make(map[string]*FirewallAnchor),
	}
}

func (s *NetdServer) AllocateTap(ctx context.Context, req *ipcv1.AllocateTapRequest) (*ipcv1.AllocateTapResponse, error) {
	requestedName := req.RequestedName
	if requestedName == "" {
		id := atomic.AddUint64(&s.counter, 1)
		requestedName = fmt.Sprintf("aegis-tap%d", id%1000)
	}

	if err := ValidateInterfaceName(requestedName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid interface name: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.allocatedTaps[requestedName]; exists {
		return nil, status.Errorf(codes.AlreadyExists, "TAP interface %q is already allocated", requestedName)
	}

	subnetIdx := (atomic.LoadUint64(&s.counter) % 250) + 2
	subnet := fmt.Sprintf("192.168.%d.0/24", subnetIdx)
	gateway := fmt.Sprintf("192.168.%d.1", subnetIdx)
	guest := fmt.Sprintf("192.168.%d.2", subnetIdx)

	if err := platformAllocateTap(ctx, requestedName, req.TargetUid, req.TargetGid, gateway, subnet); err != nil {
		return nil, status.Errorf(codes.Internal, "platform TAP allocation failed: %v", err)
	}

	info := &TapInfo{
		InterfaceName: requestedName,
		SubnetCIDR:    subnet,
		GatewayIP:     gateway,
		GuestIP:       guest,
		TargetUID:     req.TargetUid,
		TargetGID:     req.TargetGid,
	}
	s.allocatedTaps[requestedName] = info

	return &ipcv1.AllocateTapResponse{
		InterfaceName: requestedName,
		SubnetCidr:    subnet,
		GatewayIp:     gateway,
		GuestIp:       guest,
	}, nil
}

func (s *NetdServer) ReleaseTap(ctx context.Context, req *ipcv1.ReleaseTapRequest) (*ipcv1.ReleaseTapResponse, error) {
	if err := ValidateInterfaceName(req.InterfaceName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid interface name: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.allocatedTaps, req.InterfaceName)
	_ = platformReleaseTap(ctx, req.InterfaceName)

	return &ipcv1.ReleaseTapResponse{
		Success: true,
	}, nil
}

func (s *NetdServer) ApplyFirewallRules(ctx context.Context, req *ipcv1.ApplyFirewallRulesRequest) (*ipcv1.ApplyFirewallRulesResponse, error) {
	if err := ValidateInterfaceName(req.InterfaceName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid interface name: %v", err)
	}

	// Validate allowed egress targets
	for _, ipStr := range req.AllowedEgressIps {
		if err := ValidateIPOrCIDR(ipStr); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid allowed egress IP: %v", err)
		}
	}

	// Validate canary sinkholes
	for _, canaryStr := range req.CanarySinkholeIps {
		if err := ValidateIPOrCIDR(canaryStr); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid canary sinkhole IP: %v", err)
		}
	}

	anchorID := fmt.Sprintf("aegis_%d", atomic.AddUint64(&s.counter, 1))

	if err := platformApplyRules(ctx, anchorID, req.InterfaceName, req.AllowedEgressIps, req.CanarySinkholeIps); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to apply firewall rules: %v", err)
	}

	s.mu.Lock()
	s.activeAnchors[anchorID] = &FirewallAnchor{
		AnchorID:       anchorID,
		InterfaceName:  req.InterfaceName,
		AllowedEgress:  req.AllowedEgressIps,
		CanarySinkhole: req.CanarySinkholeIps,
	}
	s.mu.Unlock()

	return &ipcv1.ApplyFirewallRulesResponse{
		Success:  true,
		AnchorId: anchorID,
	}, nil
}

func (s *NetdServer) ClearFirewallRules(ctx context.Context, req *ipcv1.ClearFirewallRulesRequest) (*ipcv1.ClearFirewallRulesResponse, error) {
	if req.AnchorId != "" {
		if err := ValidateAnchorID(req.AnchorId); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid anchor ID: %v", err)
		}
	}

	s.mu.Lock()
	delete(s.activeAnchors, req.AnchorId)
	s.mu.Unlock()

	_ = platformClearRules(ctx, req.AnchorId, req.InterfaceName)

	return &ipcv1.ClearFirewallRulesResponse{
		Success: true,
	}, nil
}
