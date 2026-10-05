package vmm

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// VSockClient manages host-to-guest RPC communication with the microVM appliance.
type VSockClient struct {
	addr    string
	timeout time.Duration
}

// ExecutionRequest matches the payload expected by aegisbox-guest.
type ExecutionRequest struct {
	Command string            `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
	WorkDir string            `json:"work_dir,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`
}

// ExecutionResult is the response returned by the guest daemon.
type ExecutionResult struct {
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// NewVSockClient creates a client configured to communicate with the guest daemon.
func NewVSockClient(addr string, timeout time.Duration) *VSockClient {
	if addr == "" {
		addr = "127.0.0.1:1024"
	}
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &VSockClient{addr: addr, timeout: timeout}
}

// Execute dispatches a command payload to the microVM guest daemon and parses the result.
func (c *VSockClient) Execute(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to guest vsock daemon at %s: %w", c.addr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set connection deadline: %w", err)
	}

	data, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal execution request: %w", err)
	}

	if _, err := conn.Write(append(data, '\n')); err != nil {
		return nil, fmt.Errorf("failed to send command to guest vsock: %w", err)
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read response from guest vsock: %w", err)
	}

	var res ExecutionResult
	if err := json.Unmarshal(line, &res); err != nil {
		return nil, fmt.Errorf("invalid json response from guest: %w", err)
	}

	return &res, nil
}
