package fuzz

import (
	"context"
	"testing"

	"github.com/bonjoski/aegisbox/pkg/mcp"
)

// FuzzMCPProxy fuzzes the JSON-RPC proxy parser with arbitrary byte sequences.
func FuzzMCPProxy(f *testing.F) {
	// Seed corpus with valid and invalid JSON-RPC payloads
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"safe.txt"}}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"a","path":"b"}}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_command","arguments":{"command":"rm -rf /"}}}`))
	f.Add([]byte(`{"jsonrpc":"2.0", invalid`))
	f.Add([]byte(``))

	proxy := mcp.NewProxy(nil, nil, "/tmp/workspace", "standard")
	ctx := context.Background()

	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure that arbitrary inputs never cause a panic
		_, _, _ = proxy.ProcessClientRequest(ctx, data)
	})
}
