package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/bonjoski/aegisbox/pkg/ipc"
	"github.com/bonjoski/aegisbox/pkg/version"
)

func runApprove(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	listFlag := fs.Bool("list", false, "List all pending approval requests")
	lastFlag := fs.Bool("last", false, "Approve or deny the most recent pending intercept")
	denyFlag := fs.Bool("deny", false, "Deny the request instead of approving")
	scopeFlag := fs.String("scope", "SESSION", "Scope of the approval (ONCE, SESSION, WORKSPACE)")

	if err := fs.Parse(args); err != nil {
		return err
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

	if *listFlag {
		return listPendingApprovals(ctx, client)
	}

	decision := "APPROVE"
	if *denyFlag {
		decision = "DENY"
	}

	var interceptID string
	if *lastFlag {
		resp, err := client.ListPendingApprovals(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch pending approvals: %w", err)
		}

		if len(resp.Approvals) == 0 {
			fmt.Println("No pending approval requests found.")
			return nil
		}

		// Sort by timestamp descending to find latest
		sort.Slice(resp.Approvals, func(i, j int) bool {
			return resp.Approvals[i].TimestampNs > resp.Approvals[j].TimestampNs
		})

		interceptID = resp.Approvals[0].InterceptId
		fmt.Printf("Selected latest intercept %s (tool: %s, severity: %s)\n",
			interceptID, resp.Approvals[0].ToolName, resp.Approvals[0].Severity)
	} else if fs.NArg() > 0 {
		interceptID = fs.Arg(0)
	} else {
		return fmt.Errorf("must specify intercept ID or use --last / --list")
	}

	submitResp, err := client.SubmitApprovalDecision(ctx, interceptID, decision, *scopeFlag)
	if err != nil {
		return fmt.Errorf("failed to submit approval decision: %w", err)
	}

	if !submitResp.Acknowledged {
		return fmt.Errorf("decision rejected: %s", submitResp.ErrorMessage)
	}

	actionStr := "Approved"
	if *denyFlag {
		actionStr = "Denied"
	}
	fmt.Printf("✓ Successfully %s intercept %s [Scope: %s]\n", actionStr, interceptID, *scopeFlag)
	return nil
}

func listPendingApprovals(ctx context.Context, client *ipc.Client) error {
	resp, err := client.ListPendingApprovals(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch pending approvals: %w", err)
	}

	if len(resp.Approvals) == 0 {
		fmt.Println("No pending approval requests.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "INTERCEPT ID\tVM ID\tTOOL\tSEVERITY\tREASON\tAGE")

	now := time.Now().UnixNano()
	for _, app := range resp.Approvals {
		age := time.Duration(now - app.TimestampNs).Truncate(time.Second)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			app.InterceptId, app.VmId, app.ToolName, app.Severity, app.Reason, age)
	}

	return w.Flush()
}
