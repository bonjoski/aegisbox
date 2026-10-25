package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/bonjoski/aegisbox/pkg/ipc"
	ipcv1 "github.com/bonjoski/aegisbox/pkg/ipc/v1"
	"github.com/bonjoski/aegisbox/pkg/version"
)

func runVM(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return printVMUsage()
	}

	sub := args[0]
	switch sub {
	case "list", "ls":
		return vmList(ctx)
	case "stop":
		if len(args) < 2 {
			return fmt.Errorf("usage: aegisbox vm stop <vm-id>")
		}
		return vmStop(ctx, args[1])
	default:
		return fmt.Errorf("unknown vm subcommand %q", sub)
	}
}

func printVMUsage() error {
	fmt.Println(`Manage active microVMs via aegisboxd.

Usage:
  aegisbox vm <command>

Commands:
  list, ls         List all running microVM instances
  stop <vm-id>     Terminate a running microVM instance`)
	return nil
}

func vmList(ctx context.Context) error {
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

	resp, err := client.ListVMs(dialCtx)
	if err != nil {
		return fmt.Errorf("failed to list microVMs: %w", err)
	}

	if len(resp.Instances) == 0 {
		fmt.Println("No active microVM instances.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "VM ID\tPROFILE\tVCPU\tRAM\tUPTIME\tSTATUS\tWORKSPACE")
	for _, inst := range resp.Instances {
		uptime := fmt.Sprintf("%ds", inst.UptimeSeconds)
		if inst.UptimeSeconds > 60 {
			uptime = fmt.Sprintf("%dm%ds", inst.UptimeSeconds/60, inst.UptimeSeconds%60)
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%dMB\t%s\t%s\t%s\n",
			inst.VmId, inst.Profile, inst.VcpuCount, inst.MemoryMb, uptime, inst.Status, inst.WorkspacePath)
	}
	return w.Flush()
}

func vmStop(ctx context.Context, vmID string) error {
	socketPath, err := ipc.DefaultSocketPath()
	if err != nil {
		return err
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	client, err := ipc.NewClient(dialCtx, socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to aegisboxd (%s): %w", socketPath, err)
	}
	defer client.Close()

	if _, err := client.Authenticate(dialCtx, version.Version); err != nil {
		return fmt.Errorf("failed to authenticate with daemon: %w", err)
	}

	resp, err := client.StopVM(dialCtx, &ipcv1.StopVMRequest{
		VmId:               vmID,
		Force:              true,
		DiscardCowOverlay: true,
	})
	if err != nil {
		return fmt.Errorf("failed to stop microVM: %w", err)
	}

	if !resp.Success {
		return fmt.Errorf("failed to stop microVM: %s", resp.FailureReason)
	}

	fmt.Printf("Terminated microVM %s\n", vmID)
	return nil
}
