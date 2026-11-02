package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestSpiffeAgent_Forward(t *testing.T) {
	// 1. Mock host-side vsock server
	hostListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock host listener: %v", err)
	}
	defer hostListener.Close()

	hostAddr := hostListener.Addr().String()

	go func() {
		for {
			conn, err := hostListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				_, _ = c.Write([]byte(fmt.Sprintf("ECHO:%s", string(buf[:n]))))
			}(conn)
		}
	}()

	// 2. Setup guest-side shim
	f, err := os.CreateTemp("/tmp", "spiffe-shim-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	sockPath := f.Name()
	_ = f.Close()
	_ = os.Remove(sockPath)
	defer os.Remove(sockPath)

	agent := NewSpiffeAgent(AgentConfig{
		SocketPath:  sockPath,
		HostAddr:    hostAddr,
		DialTimeout: 2 * time.Second,
	})

	if err := agent.Start(); err != nil {
		t.Fatalf("failed to start agent: %v", err)
	}
	defer agent.Stop()

	time.Sleep(50 * time.Millisecond)

	// 3. Connect client to the guest socket
	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to connect to guest socket: %v", err)
	}
	defer clientConn.Close()

	payload := "HELLO_SPIFFE"
	if _, err := clientConn.Write([]byte(payload)); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	respBuf := make([]byte, 1024)
	n, err := clientConn.Read(respBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("read failed: %v", err)
	}

	expected := "ECHO:HELLO_SPIFFE"
	if string(respBuf[:n]) != expected {
		t.Errorf("got %q, want %q", string(respBuf[:n]), expected)
	}
}
