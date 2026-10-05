package main

import (
	"context"
	"fmt"
	"os"

	"github.com/bonjoski/aegisbox/pkg/mcp"
)

func runMCP(ctx context.Context, args []string) error {
	server := mcp.NewMCPServer(os.Stdin, os.Stdout)
	if err := server.Serve(ctx); err != nil {
		return fmt.Errorf("mcp server terminated with error: %w", err)
	}
	return nil
}
