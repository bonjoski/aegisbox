package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
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

// MCPServer manages tools, resources, and request handling for IDE agents.
type MCPServer struct {
	in   io.Reader
	out  io.Writer
	mu   sync.Mutex
	name string
	ver  string
}

// NewMCPServer returns a new MCP server.
func NewMCPServer(in io.Reader, out io.Writer) *MCPServer {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	return &MCPServer{
		in:   in,
		out:  out,
		name: "aegisbox-mcp",
		ver:  "0.1.0",
	}
}

// Serve starts listening for MCP JSON-RPC messages on standard I/O.
func (s *MCPServer) Serve(ctx context.Context) error {
	scanner := bufio.NewScanner(s.in)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
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
			s.sendError(req.ID, -32602, "Invalid params")
			return
		}

		result, err := HandleToolCall(ctx, callParams.Name, callParams.Arguments)
		if err != nil {
			s.sendResult(req.ID, map[string]interface{}{
				"content": []map[string]string{
					{
						"type": "text",
						"text": fmt.Sprintf("Error: %v", err),
					},
				},
				"isError": true,
			})
			return
		}

		s.sendResult(req.ID, map[string]interface{}{
			"content": []map[string]string{
				{
					"type": "text",
					"text": result,
				},
			},
			"isError": false,
		})

	default:
		s.sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
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
