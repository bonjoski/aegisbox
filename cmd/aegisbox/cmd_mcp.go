package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/mcp"
)

func runMCP(ctx context.Context, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "config":
			return runMCPConfig(args[1:])
		case "help", "--help", "-h":
			printMCPHelp()
			return nil
		}
	}

	server := mcp.NewMCPServer(os.Stdin, os.Stdout)
	if err := server.Serve(ctx); err != nil {
		return fmt.Errorf("mcp server terminated with error: %w", err)
	}
	return nil
}

func printMCPHelp() {
	fmt.Println(`Aegisbox Model Context Protocol (MCP) Server

Usage:
  aegisbox mcp              Start MCP JSON-RPC server over stdio for IDE agents
  aegisbox mcp config [ide] Generate configuration snippet for Cursor, Claude, or Antigravity

Supported IDEs for 'config':
  cursor        Cursor IDE (.cursor/mcp.json)
  claude        Claude Desktop (claude_desktop_config.json)
  antigravity   Google Antigravity / Gemini CLI (mcp_servers.json)
  all           Display configurations for all supported IDEs`)
}

func runMCPConfig(args []string) error {
	target := "all"
	if len(args) > 0 {
		target = strings.ToLower(args[0])
	}

	execPath, err := os.Executable()
	if err != nil {
		execPath = "aegisbox"
	} else {
		execPath, _ = filepath.EvalSymlinks(execPath)
	}

	cfg := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"aegisbox": map[string]interface{}{
				"command": execPath,
				"args":    []string{"mcp"},
			},
		},
	}

	jsonBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to generate JSON config: %w", err)
	}

	switch target {
	case "cursor":
		fmt.Println("📋 Cursor MCP Configuration (.cursor/mcp.json):")
		fmt.Println(string(jsonBytes))
	case "claude":
		fmt.Println("📋 Claude Desktop Configuration (claude_desktop_config.json):")
		fmt.Println(string(jsonBytes))
	case "antigravity", "gemini":
		fmt.Println("📋 Antigravity / Gemini CLI Configuration (mcp_servers.json):")
		fmt.Println(string(jsonBytes))
	case "all":
		fmt.Println("==================================================================")
		fmt.Println("🧩 Aegisbox Model Context Protocol (MCP) Configuration Generator")
		fmt.Println("==================================================================")
		fmt.Printf("Binary Path: %s\n\n", execPath)

		fmt.Println("1️⃣  Cursor IDE (.cursor/mcp.json or ~/.cursor/mcp.json):")
		fmt.Println(string(jsonBytes))
		fmt.Println()

		fmt.Println("2️⃣  Claude Desktop (macOS: ~/Library/Application Support/Claude/claude_desktop_config.json):")
		fmt.Println(string(jsonBytes))
		fmt.Println()

		fmt.Println("3️⃣  Google Antigravity / Gemini CLI (~/.gemini/antigravity-cli/mcp_servers.json):")
		fmt.Println(string(jsonBytes))
	default:
		return fmt.Errorf("unsupported IDE: %s (choose cursor, claude, antigravity, or all)", target)
	}

	return nil
}
