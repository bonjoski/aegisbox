package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const (
	// DefaultGuestSocket is the standard in-guest SPIFFE Workload API socket path.
	DefaultGuestSocket = "/run/spiffe/workload.sock"
	// DefaultHostVsockAddr is the standard host vsock/bridge address.
	DefaultHostVsockAddr = "127.0.0.1:9099"
)

// AgentConfig configures the in-guest SPIFFE proxy shim.
type AgentConfig struct {
	SocketPath string
	HostAddr   string
	DialTimeout time.Duration
}

// SpiffeAgent proxies guest Unix socket connections to the host vsock endpoint.
type SpiffeAgent struct {
	cfg      AgentConfig
	listener net.Listener
	closed   chan struct{}
	wg       sync.WaitGroup
}

// NewSpiffeAgent creates a new SpiffeAgent instance.
func NewSpiffeAgent(cfg AgentConfig) *SpiffeAgent {
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultGuestSocket
	}
	if cfg.HostAddr == "" {
		cfg.HostAddr = DefaultHostVsockAddr
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	return &SpiffeAgent{
		cfg:    cfg,
		closed: make(chan struct{}),
	}
}

func (a *SpiffeAgent) forward(client net.Conn) {
	defer client.Close()

	hostConn, err := net.DialTimeout("tcp", a.cfg.HostAddr, a.cfg.DialTimeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚡ [SPIFFE-Agent] Failed connecting to host vsock endpoint %s: %v\n", a.cfg.HostAddr, err)
		return
	}
	defer hostConn.Close()

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(hostConn, client)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(client, hostConn)
		errCh <- err
	}()

	<-errCh
}

// Start binds the in-guest Unix domain socket and begins forwarding connections.
func (a *SpiffeAgent) Start() error {
	dir := filepath.Dir(a.cfg.SocketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed creating socket directory %s: %w", dir, err)
	}

	if err := os.Remove(a.cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed removing stale socket %s: %w", a.cfg.SocketPath, err)
	}

	l, err := net.Listen("unix", a.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("failed listening on %s: %w", a.cfg.SocketPath, err)
	}

	// 0666 allows all in-guest containers and agents to access the workload socket
	if err := os.Chmod(a.cfg.SocketPath, 0666); err != nil {
		_ = l.Close()
		return fmt.Errorf("failed setting socket permissions: %w", err)
	}

	a.listener = l

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-a.closed:
					return
				default:
					fmt.Fprintf(os.Stderr, "⚡ [SPIFFE-Agent] Accept error: %v\n", err)
					return
				}
			}
			a.wg.Add(1)
			go func(c net.Conn) {
				defer a.wg.Done()
				a.forward(c)
			}(conn)
		}
	}()

	return nil
}

// Stop shuts down the in-guest listener and cleans up the socket file.
func (a *SpiffeAgent) Stop() error {
	close(a.closed)
	var err error
	if a.listener != nil {
		err = a.listener.Close()
	}
	if rmErr := os.Remove(a.cfg.SocketPath); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
		err = fmt.Errorf("failed removing socket %s: %w", a.cfg.SocketPath, rmErr)
	}
	a.wg.Wait()
	return err
}

func main() {
	socketFlag := flag.String("socket", DefaultGuestSocket, "In-guest Unix socket path to serve")
	hostAddrFlag := flag.String("host-addr", DefaultHostVsockAddr, "Host vsock bridge endpoint (e.g. 127.0.0.1:9099)")
	flag.Parse()

	agent := NewSpiffeAgent(AgentConfig{
		SocketPath: *socketFlag,
		HostAddr:   *hostAddrFlag,
	})

	if err := agent.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "⚡ [SPIFFE-Agent] Fatal error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("⚡ [SPIFFE-Agent] Workload shim listening on %s -> forwarding to %s\n", *socketFlag, *hostAddrFlag)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n⚡ [SPIFFE-Agent] Stopping shim...")
	_ = agent.Stop()
}
