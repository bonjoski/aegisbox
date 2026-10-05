package main

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"

	"github.com/bonjoski/ironbox/pkg/vmm"
)

func runDoctor(ctx context.Context, args []string) error {
	fmt.Printf("🔍 Running Ironbox Diagnostics for %s/%s...\n\n", runtime.GOOS, runtime.GOARCH)

	// 1. Check Git
	gitPath, err := exec.LookPath("git")
	if err != nil {
		fmt.Printf("  ❌ Git: Not found (Required for workspace worktree shadowing)\n")
	} else {
		fmt.Printf("  ✅ Git: %s\n", gitPath)
	}

	// 2. Check Hypervisor Support
	driver := vmm.NewPlatformDriver()

	fmt.Printf("  🔍 Hypervisor Engine: %s\n", driver.Name())

	if err := driver.VerifyPrerequisites(ctx); err != nil {
		fmt.Printf("     ⚠️  Hypervisor check warning: %v\n", err)
		fmt.Printf("     💡 Fallback to local process-confinement driver available.\n")
	} else {
		fmt.Printf("     ✅ Hardware Virtualization support verified.\n")
	}

	// 3. Check Network Packet Filter Capabilities
	if runtime.GOOS == "darwin" {
		pfctlPath, err := exec.LookPath("pfctl")
		if err != nil {
			fmt.Printf("  ❌ pfctl: Not found\n")
		} else {
			fmt.Printf("  ✅ macOS Packet Filter: %s\n", pfctlPath)
		}
	} else if runtime.GOOS == "linux" {
		nftPath, err := exec.LookPath("nft")
		if err != nil {
			fmt.Printf("  ⚠️  nftables: Not found (iptables fallback required)\n")
		} else {
			fmt.Printf("  ✅ Linux nftables: %s\n", nftPath)
		}
	}

	fmt.Println("\n✨ Diagnostics complete. System ready for Ironbox sandboxed execution.")
	return nil
}
