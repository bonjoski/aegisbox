package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf8"

	"github.com/bonjoski/aegisbox/pkg/telemetry"
)

var (
	ErrDuplicateKeyInJSON = errors.New("security violation: duplicate key detected in JSON-RPC payload")
	ErrInvalidUTF8        = errors.New("security violation: invalid UTF-8 encoding in JSON-RPC payload")
	ErrExecutionDenied    = errors.New("execution denied by Aegisbox policy")
)

// PolicyEvaluator abstracts the CEL policy engine.
type PolicyEvaluator interface {
	EvaluateToolCall(ctx context.Context, toolName string, args map[string]any, workspace, profile string) (Decision, error)
}

// Decision represents the outcome of a policy check.
type Decision string

const (
	DecisionAllow             Decision = "ALLOW"
	DecisionInterceptApproval Decision = "INTERCEPT_APPROVAL"
	DecisionDeny              Decision = "DENY"
)

// InterceptHandler is invoked when a tool call requires human-in-the-loop authorization.
type InterceptHandler func(ctx context.Context, toolName string, args map[string]any, severity, reason string) (bool, error)

// Proxy wraps bidirectional JSON-RPC communication with policy evaluation and normalized re-serialization.
type Proxy struct {
	evaluator PolicyEvaluator
	onReview  InterceptHandler
	workspace string
	profile   string
	mu        sync.Mutex
}

// NewProxy creates a new MCP security proxy.
func NewProxy(evaluator PolicyEvaluator, onReview InterceptHandler, workspace, profile string) *Proxy {
	return &Proxy{
		evaluator: evaluator,
		onReview:  onReview,
		workspace: workspace,
		profile:   profile,
	}
}

// ValidateJSONStream checks for valid UTF-8 and strictly forbids duplicate keys.
func ValidateJSONStream(data []byte) error {
	if !utf8.Valid(data) {
		return ErrInvalidUTF8
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	return checkDuplicateKeys(dec)
}

func checkDuplicateKeys(dec *json.Decoder) error {
	t, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}

	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}

	switch delim {
	case '{':
		keys := make(map[string]bool)
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key := keyToken.(string)
			if keys[key] {
				return fmt.Errorf("%w: duplicate key %q", ErrDuplicateKeyInJSON, key)
			}
			keys[key] = true

			// Parse value recursively
			if err := checkDuplicateKeys(dec); err != nil {
				return err
			}
		}
		// Consume closing '}'
		_, _ = dec.Token()
	case '[':
		for dec.More() {
			if err := checkDuplicateKeys(dec); err != nil {
				return err
			}
		}
		// Consume closing ']'
		_, _ = dec.Token()
	}
	return nil
}

// ProcessClientRequest inspects an incoming client request, enforces policy, and returns re-serialized bytes.
func (p *Proxy) ProcessClientRequest(ctx context.Context, raw []byte) ([]byte, *JSONRPCResponse, error) {
	if err := ValidateJSONStream(raw); err != nil {
		return nil, &JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &RPCError{
				Code:    -32700,
				Message: fmt.Sprintf("Parse error: %v", err),
			},
		}, nil
	}

	var req JSONRPCRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, &JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &RPCError{
				Code:    -32600,
				Message: "Invalid Request",
			},
		}, nil
	}

	// Intercept tools/call
	if req.Method == "tools/call" {
		var toolCall struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &toolCall); err != nil {
			return nil, &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &RPCError{
					Code:    -32602,
					Message: "Invalid params for tools/call",
				},
			}, nil
		}

		if p.evaluator != nil {
			decision, err := p.evaluator.EvaluateToolCall(ctx, toolCall.Name, toolCall.Arguments, p.workspace, p.profile)
			telemetry.LogMCP("mcp", toolCall.Name, fmt.Sprintf("%v", toolCall.Arguments), string(decision))
			if err != nil {
				telemetry.Log("mcp", fmt.Sprintf("CEL evaluation error: %v", err), "stderr")
				return nil, &JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error: &RPCError{
						Code:    -32603,
						Message: fmt.Sprintf("Policy evaluation error: %v", err),
					},
				}, nil
			}

			switch decision {
			case DecisionDeny:
				telemetry.LogTripwire("mcp", fmt.Sprintf("CEL Policy DENIED tool execution: %s (%v)", toolCall.Name, toolCall.Arguments), "169.254.169.254")
				return nil, &JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      req.ID,
					Error: &RPCError{
						Code:    -32000,
						Message: "Security violation: execution blocked by Aegisbox policy",
					},
				}, nil

			case DecisionInterceptApproval:
				telemetry.LogTripwire("mcp", fmt.Sprintf("CEL Policy QUARANTINED tool execution (awaiting human approval): %s", toolCall.Name), "169.254.169.254")
				if p.onReview == nil {
					return nil, &JSONRPCResponse{
						JSONRPC: "2.0",
						ID:      req.ID,
						Error: &RPCError{
							Code:    -32001,
							Message: "Execution requires human-in-the-loop approval, but no reviewer is connected",
						},
					}, nil
				}

				approved, err := p.onReview(ctx, toolCall.Name, toolCall.Arguments, "HIGH", "Sensitive tool action intercepted")
				if err != nil || !approved {
					return nil, &JSONRPCResponse{
						JSONRPC: "2.0",
						ID:      req.ID,
						Error: &RPCError{
							Code:    -32001,
							Message: "Execution denied by human-in-the-loop reviewer",
						},
					}, nil
				}
			}
		}

		// Re-serialization Defense: Re-marshal the sanitized AST rather than forwarding raw bytes
		sanitizedParams, err := json.Marshal(toolCall)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to re-marshal sanitized tool call: %w", err)
		}
		req.Params = sanitizedParams
	}

	// Canonical re-serialization of the request
	reSerialized, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to re-serialize canonical JSON-RPC request: %w", err)
	}

	return reSerialized, nil, nil
}
