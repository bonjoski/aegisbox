package mcp

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestVSockProxy_ForwardAndMediate(t *testing.T) {
	// 1. Mock guest MCP server
	guestLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock guest server: %v", err)
	}
	defer guestLn.Close()

	guestAddr := guestLn.Addr().String()

	// Guest server loop
	go func() {
		for {
			conn, err := guestLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					line := scanner.Bytes()
					if len(line) == 0 {
						continue
					}
					// Reply with valid MCP response
					reply := []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello from guest"}]}}` + "\n")
					_, _ = c.Write(reply)
				}
			}(conn)
		}
	}()

	celEngine, err := NewCELPolicyEngine()
	if err != nil {
		t.Fatalf("failed to create CEL engine: %v", err)
	}

	proxy := NewProxy(celEngine, nil, "/workspace", "standard")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Valid tool call
	reqPayload := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe_tool","arguments":{"input":"test"}}}` + "\n")
	clientIn := bytes.NewReader(reqPayload)
	var clientOut bytes.Buffer

	bridgeErr := proxy.RunVSockProxy(ctx, clientIn, &clientOut, guestAddr)
	if bridgeErr != nil && bridgeErr != context.Canceled {
		t.Logf("bridge ended with: %v", bridgeErr)
	}

	outStr := clientOut.String()
	if !strings.Contains(outStr, "hello from guest") {
		t.Errorf("expected response from guest MCP server, got: %s", outStr)
	}
}

func TestVSockBridge_Listener(t *testing.T) {
	// 1. Mock guest MCP server
	guestLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock guest server: %v", err)
	}
	defer guestLn.Close()
	guestAddr := guestLn.Addr().String()

	go func() {
		for {
			conn, err := guestLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					reply := []byte(`{"jsonrpc":"2.0","id":2,"result":{"status":"ok"}}` + "\n")
					_, _ = c.Write(reply)
				}
			}(conn)
		}
	}()

	proxy := NewProxy(nil, nil, "/workspace", "standard")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	bridge, err := NewVSockBridge(proxy, guestAddr, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create bridge: %v", err)
	}
	defer bridge.Close()

	go func() {
		_ = bridge.Serve(ctx)
	}()

	time.Sleep(50 * time.Millisecond)

	// Connect a client to bridge
	conn, err := net.Dial("tcp", bridge.Addr().String())
	if err != nil {
		t.Fatalf("failed to connect to bridge: %v", err)
	}
	defer conn.Close()

	req := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ping","arguments":{}}}` + "\n")
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("failed to write to bridge: %v", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("failed to read from bridge: %v", err)
	}

	if !strings.Contains(line, `"status":"ok"`) {
		t.Errorf("unexpected bridge response: %s", line)
	}
}
