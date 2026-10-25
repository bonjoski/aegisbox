package mcp

import (
	"context"
	"fmt"
	"io"
	"net"
)

// RunVSockProxy connects to an in-guest microVM MCP server at guestAddr (e.g. "127.0.0.1:50051"
// or vsock bridge endpoint) and proxies communication between the host client and the guest server.
func (p *Proxy) RunVSockProxy(ctx context.Context, clientIn io.Reader, clientOut io.Writer, guestAddr string) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", guestAddr)
	if err != nil {
		return fmt.Errorf("failed to dial guest vsock MCP endpoint %s: %w", guestAddr, err)
	}
	defer conn.Close()

	return p.RunStdioPipeProxy(ctx, clientIn, clientOut, conn, conn)
}

// VSockBridge handles bridging host MCP requests to guest microVM over vsock / TCP stream.
type VSockBridge struct {
	proxy     *Proxy
	guestAddr string
	listener  net.Listener
}

// NewVSockBridge creates a new VSockBridge listening on listenAddr (e.g. host unix socket or localhost port).
func NewVSockBridge(proxy *Proxy, guestAddr string, network, listenAddr string) (*VSockBridge, error) {
	ln, err := net.Listen(network, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind vsock bridge listener: %w", err)
	}

	return &VSockBridge{
		proxy:     proxy,
		guestAddr: guestAddr,
		listener:  ln,
	}, nil
}

// Serve accepts client connections and routes them through the MCP firewall to the guest.
func (b *VSockBridge) Serve(ctx context.Context) error {
	defer b.listener.Close()

	for {
		conn, err := b.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				return err
			}
		}

		go func(c net.Conn) {
			defer c.Close()
			_ = b.proxy.RunVSockProxy(ctx, c, c, b.guestAddr)
		}(conn)
	}
}

// Addr returns the listener address.
func (b *VSockBridge) Addr() net.Addr {
	return b.listener.Addr()
}

// Close closes the underlying listener.
func (b *VSockBridge) Close() error {
	return b.listener.Close()
}
