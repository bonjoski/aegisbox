package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/bonjoski/aegisbox/pkg/version"
)

// JSONRPCRequest represents a standard MCP/JSON-RPC request message.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a standard MCP/JSON-RPC response message.
type JSONRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

// RPCError provides error codes and messages for JSON-RPC.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ServerOptions configures the security posture of the MCP server.
type ServerOptions struct {
	AllowDegradedLocal bool
	Profile            string
}

// MCPServer manages tools, resources, and request handling for IDE agents.
type MCPServer struct {
	in        io.Reader
	out       io.Writer
	mu        sync.Mutex
	name      string
	ver       string
	opts      ServerOptions
	evaluator PolicyEvaluator
	initErr   error
}

// NewMCPServer returns a new fail-closed MCP server (requiring hardware hypervisor unless explicitly configured).
func NewMCPServer(in io.Reader, out io.Writer) *MCPServer {
	return NewMCPServerWithOptions(in, out, ServerOptions{})
}

// NewMCPServerWithOptions returns a new MCP server with explicit operator options.
func NewMCPServerWithOptions(in io.Reader, out io.Writer, opts ServerOptions) *MCPServer {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	if opts.Profile == "" {
		opts.Profile = "microvm-hardened"
	}
	celEngine, err := NewCELPolicyEngine()
	return &MCPServer{
		in:        in,
		out:       out,
		name:      "aegisbox-mcp",
		ver:       version.Version,
		opts:      opts,
		evaluator: celEngine,
		initErr:   err,
	}
}

// Serve starts listening for MCP JSON-RPC messages on standard I/O with duplicate-key
// JSON stream validation and CEL policy enforcement.
func (s *MCPServer) Serve(ctx context.Context) error {
	scanner := bufio.NewScanner(s.in)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		// Enforce UTF-8 validity and reject duplicate JSON keys before unmarshaling
		if err := ValidateJSONStream(line); err != nil {
			s.sendError(nil, -32700, fmt.Sprintf("Parse error: %v", err))
			continue
		}

		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, -32700, "Parse error")
			continue
		}

		s.handleRequest(ctx, req)
	}

	return scanner.Err()
}

func (s *MCPServer) handleRequest(ctx context.Context, req JSONRPCRequest) {
	isNotification := req.ID == nil

	switch req.Method {
	case "initialize":
		s.sendResult(req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]string{
				"name":    s.name,
				"version": s.ver,
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]bool{
					"listChanged": false,
				},
			},
		})

	case "notifications/initialized", "initialized":
		return

	case "ping":
		if !isNotification {
			s.sendResult(req.ID, map[string]interface{}{})
		}

	case "tools/list":
		s.sendResult(req.ID, map[string]interface{}{
			"tools": GetAvailableTools(),
		})

	case "tools/call":
		var callParams struct {
			Name      string                 `json:"name"`
			Arguments map[string]interface{} `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			if !isNotification {
				s.sendError(req.ID, -32602, "Invalid params")
			}
			return
		}

		// Fail closed if CEL policy engine failed to initialize or denies/quarantines the tool call
		if s.initErr != nil || s.evaluator == nil {
			if !isNotification {
				s.sendError(req.ID, -32603, "Policy engine unavailable (fail-closed)")
			}
			return
		}

		cwd, _ := os.Getwd()
		decision, evalErr := s.evaluator.EvaluateToolCall(ctx, callParams.Name, callParams.Arguments, cwd, s.opts.Profile)
		if evalErr != nil || decision == DecisionDeny {
			if !isNotification {
				s.sendError(req.ID, -32000, "Security violation: execution blocked by Aegisbox CEL policy")
			}
			return
		}
		if decision == DecisionInterceptApproval {
			if !isNotification {
				s.sendError(req.ID, -32001, "Execution requires human-in-the-loop approval")
			}
			return
		}

		result, err := HandleToolCallWithConfig(ctx, callParams.Name, callParams.Arguments, ToolConfig{
			AllowDegradedLocal: s.opts.AllowDegradedLocal,
		})
		if err != nil {
			if !isNotification {
				s.sendResult(req.ID, map[string]interface{}{
					"content": []map[string]string{
						{
							"type": "text",
							"text": fmt.Sprintf("Error: %v", err),
						},
					},
					"isError": true,
				})
			}
			return
		}

		if !isNotification {
			s.sendResult(req.ID, map[string]interface{}{
				"content": []map[string]string{
					{
						"type": "text",
						"text": result,
					},
				},
				"isError": false,
			})
		}

	default:
		if !isNotification {
			s.sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
		}
	}
}

func (s *MCPServer) sendResult(id interface{}, result interface{}) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	data, _ := json.Marshal(resp)
	fmt.Fprintf(s.out, "%s\n", data)
}

func (s *MCPServer) sendError(id interface{}, code int, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: msg,
		},
	}
	data, _ := json.Marshal(resp)
	fmt.Fprintf(s.out, "%s\n", data)
}
