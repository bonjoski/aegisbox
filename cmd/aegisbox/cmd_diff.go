package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bonjoski/aegisbox/pkg/workspace"
)

func runDiff(ctx context.Context, args []string) error {
	diffFlags := flag.NewFlagSet("diff", flag.ExitOnError)
	sessionID := diffFlags.String("session", "", "Specific session ID to inspect")
	apply := diffFlags.Bool("apply", false, "Apply isolated changes to the current host workspace")

	diffFlags.Usage = func() {
		fmt.Println("Usage: aegisbox diff [flags]")
		diffFlags.PrintDefaults()
	}

	if err := diffFlags.Parse(args); err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	mgr, err := workspace.NewWorkspaceManager("")
	if err != nil {
		return fmt.Errorf("failed to initialize workspace manager: %w", err)
	}

	fmt.Println("🔍 Aegisbox Workspace Delta Inspector")

	// If no specific session given, check if any shadow directories exist in temp
	baseTmp := os.TempDir()
	pattern := filepath.Join(baseTmp, "aegisbox-*")
	matches, _ := filepath.Glob(pattern)

	if len(matches) == 0 && *sessionID == "" {
		fmt.Println("ℹ️  No active ephemeral sessions found in staging.")
		fmt.Println("   Any changes produced by 'aegisbox exec' without --apply were safely quarantined.")
		return nil
	}

	targetDir := ""
	if *sessionID != "" {
		targetDir = filepath.Join(baseTmp, fmt.Sprintf("aegisbox-%s", *sessionID))
	} else if len(matches) > 0 {
		targetDir = matches[len(matches)-1] // latest session
	}

	if _, err := os.Stat(targetDir); os.IsNotExist(err) {
		fmt.Printf("Session directory not found: %s\n", targetDir)
		return nil
	}

	fmt.Printf("📂 Inspecting staged session: %s\n", filepath.Base(targetDir))

	// Reconstruct session to capture diff
	session, err := mgr.CreateSession(ctx, workspace.ShadowConfig{
		BaseDir: cwd,
		Mode:    workspace.ModeGitWorktree,
	})
	if err != nil {
		return fmt.Errorf("failed to inspect workspace session: %w", err)
	}
	defer session.Cleanup(ctx)

	diff, err := session.CaptureDiff(ctx)
	if err != nil {
		return fmt.Errorf("failed to capture diff: %w", err)
	}

	if len(diff.FilesAdded) == 0 && len(diff.FilesModified) == 0 && len(diff.FilesDeleted) == 0 {
		fmt.Println("✨ Clean workspace: No file modifications detected.")
		return nil
	}

	fmt.Printf("Delta Summary: %d added, %d modified, %d deleted\n",
		len(diff.FilesAdded), len(diff.FilesModified), len(diff.FilesDeleted))

	for _, f := range diff.FilesAdded {
		fmt.Printf("  + [ADD] %s\n", f)
	}
	for _, f := range diff.FilesModified {
		fmt.Printf("  ~ [MOD] %s\n", f)
	}
	for _, f := range diff.FilesDeleted {
		fmt.Printf("  - [DEL] %s\n", f)
	}

	if *apply {
		fmt.Println("💾 Applying changes to host workspace...")
		if err := session.ApplyToHost(ctx); err != nil {
			return fmt.Errorf("failed to apply changes: %w", err)
		}
		fmt.Println("✅ Changes applied successfully.")
	}

	return nil
}
