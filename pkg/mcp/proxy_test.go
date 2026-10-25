package mcp

import (
	"context"
	"strings"
	"testing"
)

func TestProxy_DuplicateKeyRejection(t *testing.T) {
	proxy := NewProxy(nil, nil, "/tmp", "standard")

	// Payload with duplicate "path" key
	maliciousPayload := []byte(`{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "tools/call",
		"params": {
			"name": "read_file",
			"arguments": {
				"path": "/workspace/safe.txt",
				"path": "/etc/shadow"
			}
		}
	}`)

	_, resp, err := proxy.ProcessClientRequest(context.Background(), maliciousPayload)
	if err != nil {
		t.Fatalf("unexpected internal error: %v", err)
	}

	if resp == nil || resp.Error == nil {
		t.Fatalf("expected error response rejecting duplicate key, but got success")
	}

	if !strings.Contains(resp.Error.Message, "duplicate key") {
		t.Errorf("expected error message to mention duplicate key, got: %s", resp.Error.Message)
	}
}

func TestProxy_CELPolicyEnforcement(t *testing.T) {
	celEngine, err := NewCELPolicyEngine()
	if err != nil {
		t.Fatalf("failed to create CEL engine: %v", err)
	}

	reviewed := false
	onReview := func(ctx context.Context, toolName string, args map[string]any, severity, reason string) (bool, error) {
		reviewed = true
		return true, nil // Approve
	}

	proxy := NewProxy(celEngine, onReview, "/tmp", "microvm-hardened")
	ctx := context.Background()

	// 1. Destructive command -> Must be DENIED immediately
	destructivePayload := []byte(`{
		"jsonrpc": "2.0",
		"id": 10,
		"method": "tools/call",
		"params": {
			"name": "run_command",
			"arguments": {
				"command": "rm -rf / --no-preserve-root"
			}
		}
	}`)

	_, resp, err := proxy.ProcessClientRequest(ctx, destructivePayload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.Error == nil || resp.Error.Code != -32000 {
		t.Fatalf("expected code -32000 for policy denial, got: %v", resp)
	}

	// 2. Sensitive credential read -> Must trigger Intercept Reviewer
	credentialPayload := []byte(`{
		"jsonrpc": "2.0",
		"id": 20,
		"method": "tools/call",
		"params": {
			"name": "read_file",
			"arguments": {
				"path": "/project/.env"
			}
		}
	}`)

	reSerialized, resp, err := proxy.ProcessClientRequest(ctx, credentialPayload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reviewed {
		t.Errorf("expected sensitive credential access to invoke review handler")
	}
	if resp != nil {
		t.Errorf("expected approved request to forward without error response, got: %v", resp)
	}
	if len(reSerialized) == 0 {
		t.Errorf("expected re-serialized bytes on approval")
	}

	// 3. Benign operation -> Must be ALLOWED without review
	reviewed = false
	benignPayload := []byte(`{
		"jsonrpc": "2.0",
		"id": 30,
		"method": "tools/call",
		"params": {
			"name": "read_file",
			"arguments": {
				"path": "src/main.go"
			}
		}
	}`)

	reSerialized, resp, err = proxy.ProcessClientRequest(ctx, benignPayload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reviewed {
		t.Errorf("benign operation should not trigger human review")
	}
	if resp != nil {
		t.Errorf("expected benign operation to succeed without error response")
	}
	if !strings.Contains(string(reSerialized), "src/main.go") {
		t.Errorf("expected canonical re-serialization to preserve argument")
	}
}
