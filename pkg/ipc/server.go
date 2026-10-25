package ipc

import (
	"context"
	"net"
	"sync"
	"time"

	ipcv1 "github.com/bonjoski/aegisbox/pkg/ipc/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Server wraps the gRPC server and enforces token authentication across all methods.
type Server struct {
	grpcServer *grpc.Server
	tokens     *TokenStore
	listener   net.Listener
	mu         sync.Mutex
	running    bool
}

// NewServer initializes an IPC server with an integrated session token store.
func NewServer(tokens *TokenStore) *Server {
	if tokens == nil {
		tokens = NewTokenStore(24 * time.Hour)
	}

	s := &Server{
		tokens: tokens,
	}

	authUnaryInterceptor := func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		// Handshake does not require a prior session token
		if info.FullMethod == "/aegisbox.daemon.v1.AegisboxDaemonService/Handshake" {
			return handler(ctx, req)
		}

		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata context")
		}

		tokenVals := md.Get("x-aegisbox-session-token")
		if len(tokenVals) == 0 || !s.tokens.ValidateToken(tokenVals[0]) {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired session token")
		}

		return handler(ctx, req)
	}

	authStreamInterceptor := func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, "missing metadata context")
		}

		tokenVals := md.Get("x-aegisbox-session-token")
		if len(tokenVals) == 0 || !s.tokens.ValidateToken(tokenVals[0]) {
			return status.Error(codes.Unauthenticated, "invalid or expired session token")
		}

		return handler(srv, ss)
	}

	s.grpcServer = grpc.NewServer(
		grpc.UnaryInterceptor(authUnaryInterceptor),
		grpc.StreamInterceptor(authStreamInterceptor),
	)

	return s
}

// RegisterDaemonService binds the AegisboxDaemonService implementation to this server.
func (s *Server) RegisterDaemonService(impl ipcv1.AegisboxDaemonServiceServer) {
	ipcv1.RegisterAegisboxDaemonServiceServer(s.grpcServer, impl)
}

// Serve starts the server on the provided secure listener.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	s.listener = l
	s.running = true
	s.mu.Unlock()

	return s.grpcServer.Serve(l)
}

// TokenStore returns the underlying token manager.
func (s *Server) TokenStore() *TokenStore {
	return s.tokens
}

// GracefulStop gracefully stops the gRPC server and closes the listener.
func (s *Server) GracefulStop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		s.grpcServer.GracefulStop()
		s.running = false
	}
}

// Stop forcefully terminates the server.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		s.grpcServer.Stop()
		s.running = false
	}
}
