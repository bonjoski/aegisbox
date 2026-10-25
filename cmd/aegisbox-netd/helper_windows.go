//go:build windows

package main

import (
	"context"
)

func platformAllocateTap(ctx context.Context, name string, uid, gid uint32, gateway, subnet string) error {
	// Handled via Windows Filtering Platform (WFP) and Hyper-V Virtual Switch NetAdapter
	return nil
}

func platformReleaseTap(ctx context.Context, name string) error {
	return nil
}

func platformApplyRules(ctx context.Context, anchorID, iface string, allowedIPs, canaryIPs []string) error {
	return nil
}

func platformClearRules(ctx context.Context, anchorID, iface string) error {
	return nil
}
