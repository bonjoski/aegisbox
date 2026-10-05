package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bonjoski/aegisbox/pkg/mcp"
)

func TestMCPServer_InitializeAndListTools(t *testing.T) {
	ctx := context.Background()

	// 1. Initialize Request
	initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n"
	listReq := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n"

	in := strings.NewReader(initReq + listReq)
	var out bytes.Buffer

	server := mcp.NewMCPServer(in, &out)
	if err := server.Serve(ctx); err != nil {
		t.Fatalf("MCP serve failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 responses, got %d", len(lines))
	}

	var initResp mcp.JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
		t.Fatalf("failed to unmarshal init response: %v", err)
	}
	if initResp.Error != nil {
		t.Errorf("unexpected error in init response: %+v", initResp.Error)
	}

	var listResp mcp.JSONRPCResponse
	if err := json.Unmarshal([]byte(lines[1]), &listResp); err != nil {
		t.Fatalf("failed to unmarshal list response: %v", err)
	}
	if listResp.Error != nil {
		t.Errorf("unexpected error in list response: %+v", listResp.Error)
	}
}

func TestMCPServer_ToolCallVet(t *testing.T) {
	ctx := context.Background()

	res, err := mcp.HandleToolCall(ctx, "aegisbox_vet", map[string]interface{}{
		"command": "go test ./...",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(res, "Pre-Flight Gate PASSED") {
		t.Errorf("expected clean command to pass vet, got: %s", res)
	}
}
