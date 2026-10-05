package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"
)


// DefaultVSockPort is the standard guest daemon listening port.
const DefaultVSockPort = 1024

// ExecutionRequest is the JSON payload sent from host to guest over vsock.
type ExecutionRequest struct {
	Command string            `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
	WorkDir string            `json:"work_dir,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`
}

// ExecutionResponse is streamed back from guest to host.
type ExecutionResponse struct {
	Stdout   string `json:"stdout,omitempty"`
	Stderr   string `json:"stderr,omitempty"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

func main() {
	fmt.Println("🛡️  Aegisbox Guest Agent Daemon v0.1.0 starting inside microVM...")

	// Listen on local socket / vsock
	addr := fmt.Sprintf("127.0.0.1:%d", DefaultVSockPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to bind guest listener: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("✅ Guest daemon listening on %s (Ready for host RPCs)\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Connection read error: %v\n", err)
			}
			return
		}

		var req ExecutionRequest
		if err := json.Unmarshal(line, &req); err != nil {
			resp := ExecutionResponse{
				ExitCode: -1,
				Error:    fmt.Sprintf("Invalid JSON request: %v", err),
			}
			data, _ := json.Marshal(resp)
			_, _ = conn.Write(append(data, '\n'))
			continue
		}

		resp := executeCommand(req)
		data, err := json.Marshal(resp)
		if err == nil {
			_, _ = conn.Write(append(data, '\n'))
		}
	}
}

func executeCommand(req ExecutionRequest) ExecutionResponse {
	ctx := context.Background()
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, "sh", "-c", req.Command)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}

	// Environment sanitization
	envList := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"AEGISBOX_GUEST_ACTIVE=1",
	}
	for k, v := range req.Env {
		envList = append(envList, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = envList

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	errMsg := ""

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
			errMsg = err.Error()
		}
	}

	return ExecutionResponse{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Error:    errMsg,
	}
}
