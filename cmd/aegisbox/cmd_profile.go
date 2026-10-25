package main

import (
	"context"
	"fmt"
	"time"

	"github.com/bonjoski/aegisbox/pkg/ipc"
	"github.com/bonjoski/aegisbox/pkg/version"
)

func runProfile(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("subcommand required: get, set <profile>")
	}

	socketPath, err := ipc.DefaultSocketPath()
	if err != nil {
		return err
	}

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client, err := ipc.NewClient(dialCtx, socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to aegisboxd (%s): %w", socketPath, err)
	}
	defer client.Close()

	if _, err := client.Authenticate(dialCtx, version.Version); err != nil {
		return fmt.Errorf("failed to authenticate with daemon: %w", err)
	}

	switch args[0] {
	case "get":
		resp, err := client.GetProfile(ctx)
		if err != nil {
			return fmt.Errorf("failed to get active profile: %w", err)
		}

		mdmStr := "unlocked"
		if resp.MdmLocked {
			mdmStr = "locked by enterprise policy"
		}

		fmt.Printf("Active Profile: %s (%s)\n", resp.ActiveProfile, mdmStr)
		return nil

	case "set":
		if len(args) < 2 {
			return fmt.Errorf("missing profile name (permissive, standard, microvm-hardened)")
		}

		targetProfile := args[1]
		resp, err := client.SetProfile(ctx, targetProfile)
		if err != nil {
			return fmt.Errorf("failed to set profile: %w", err)
		}

		if !resp.Success {
			return fmt.Errorf("failed to activate profile %s: %s", targetProfile, resp.ErrorMessage)
		}

		fmt.Printf("✓ Active security profile updated to: %s\n", resp.ActiveProfile)
		return nil

	default:
		return fmt.Errorf("unknown profile subcommand %q. Available: get, set", args[0])
	}
}
