package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/bonjoski/aegisbox/pkg/bridge"
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

var (
	activeGuestInitMu sync.RWMutex
	activeGuestInit   *bridge.GuestInit
)

func main() {
	var (
		portFlag       = flag.Int("port", DefaultVSockPort, "Port to listen on for vsock/TCP RPCs")
		addrFlag       = flag.String("addr", "", "Override full address to bind (e.g. 127.0.0.1:0)")
		signalPortFlag = flag.Int("signal-port", int(bridge.SignalPort), "Port to listen on for vsock signal protocol (default 0x5161)")
		signalAddrFlag = flag.String("signal-addr", "", "Override signal address to bind (e.g. 127.0.0.1:0)")
	)
	flag.Parse()

	addr := *addrFlag
	if addr == "" {
		addr = fmt.Sprintf("127.0.0.1:%d", *portFlag)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to bind guest listener: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	actualAddr := listener.Addr().String()
	fmt.Printf("✅ Guest daemon listening on %s (Ready for host RPCs)\n", actualAddr)

	// Bind signal bridge listener
	sigAddr := *signalAddrFlag
	if sigAddr == "" {
		if strings.Contains(addr, ":0") {
			sigAddr = "127.0.0.1:0"
		} else {
			sigAddr = fmt.Sprintf("127.0.0.1:%d", *signalPortFlag)
		}
	}

	sigListener, err := net.Listen("tcp", sigAddr)
	if err == nil {
		defer sigListener.Close()
		fmt.Printf("✅ Guest signal bridge listening on %s (Port 0x%x)\n", sigListener.Addr().String(), bridge.SignalPort)

		go func() {
			for {
				sConn, err := sigListener.Accept()
				if err != nil {
					return
				}
				gi := bridge.NewGuestInit(sConn, bridge.GuestInitOpts{
					OnWatchdogTimeout: func() {
						fmt.Fprintln(os.Stderr, "⚠️  [Guest] Watchdog timeout: Host heartbeat lost. Halting.")
					},
					OnSignalReceived: func(sig syscall.Signal) {
						fmt.Fprintf(os.Stderr, "⚡ [Guest] Signal received over vsock: %v\n", sig)
					},
				})
				activeGuestInitMu.Lock()
				if activeGuestInit != nil {
					_ = activeGuestInit.Close()
				}
				activeGuestInit = gi
				activeGuestInitMu.Unlock()
			}
		}()
	} else {
		fmt.Fprintf(os.Stderr, "⚠️  Failed to bind guest signal listener: %v\n", err)
	}

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

	// Put child into its own process group so signals propagate to entire tree
	setProcessGroup(cmd)

	if err := cmd.Start(); err != nil {
		return ExecutionResponse{
			Stdout:   "",
			Stderr:   err.Error(),
			ExitCode: -1,
			Error:    err.Error(),
		}
	}

	activeGuestInitMu.RLock()
	gi := activeGuestInit
	activeGuestInitMu.RUnlock()

	if gi != nil && cmd.Process != nil {
		gi.SetTargetProcess(cmd.Process.Pid, cmd.Process.Pid)
	}

	err := cmd.Wait()

	if gi != nil {
		gi.SetTargetProcess(0, 0)
	}

	exitCode := 0
	errMsg := ""

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
			if exitCode == 137 && gi != nil {
				// Process killed via SIGKILL / OOM event
				_ = gi.ReportOOM(1)
			}
		} else {
			exitCode = -1
			errMsg = err.Error()
		}
	}

	if gi != nil {
		_ = gi.ReportExit(exitCode)
	}

	return ExecutionResponse{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: exitCode,
		Error:    errMsg,
	}
}
