package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bonjoski/aegisbox/pkg/ux"
)

func runExplain(args []string) error {
	return runExplainTo(args, os.Stdout, os.Stderr)
}

func runExplainTo(args []string, stdout, stderr io.Writer) error {
	asJSON := false
	topic := "microvm"

	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--why":
			// explain always renders full --why progressive disclosure
		case "-h", "--help", "help":
			_, _ = fmt.Fprintln(stdout, "Usage: aegisbox explain [microvm|katas|ai-safety|loopback|cow|degraded-local] [--why] [--json]")
			return nil
		default:
			if !strings.HasPrefix(a, "-") {
				topic = strings.ToLower(strings.TrimSpace(a))
			}
		}
	}

	explanations := map[string]*ux.FixForwardError{
		"microvm": {
			Tool:           "aegisbox",
			Code:           "AEGISBOX_EXPLAIN_MICROVM",
			Summary:        "Hardware-isolated Tier-2 microVM containment (Apple VZ / KVM Firecracker / Hyper-V)",
			RemediationCmd: "aegisbox doctor",
			WhyOneLiner:    "Runs untrusted AI agent shells and package install hooks inside a disposable guest kernel with zero host access.",
			DeepWhy:        "Aegisbox boots a minimal Alpine SquashFS appliance over virtio-vsock so even kernel-level exploits or postinstall scripts cannot read host ~/.ssh, ~/.aws, or .env files. Per invariant AEG-01, Aegisbox fails closed when hypervisor prerequisites are missing unless --allow-degraded-local is explicitly passed.",
			References:     []string{"OWASP-LLM06", "CWE-250", "docs/use-cases/01-untrusted-repo-detonation.md"},
			ExitCode:       0,
		},
		"katas": {
			Tool:           "aegisbox",
			Code:           "AEGISBOX_EXPLAIN_KATAS",
			Summary:        "2-minute offline local security katas with hands-on editable workspaces (`aegisbox learn`)",
			RemediationCmd: "aegisbox learn list",
			WhyOneLiner:    "Lets developers watch realistic slopsquat, .env, RAG, MCP, and egress exploits break—then fix them in 5 lines offline.",
			DeepWhy:        "Export a self-contained 0700 workspace with `aegisbox learn kata-03-rag-injection --export-dir ./kata-lab`, edit `handler.go` to apply the paved-road fix, and run `aegisbox learn kata-03-rag-injection --workspace ./kata-lab --check`. Zero API keys and zero host $HOME access required.",
			References:     []string{"OWASP-LLM01", "OWASP-LLM06", "docs/use-cases/02-two-minute-security-katas.md"},
			ExitCode:       0,
		},
		"ai-safety": {
			Tool:           "aegisbox",
			Code:           "AEGISBOX_EXPLAIN_AI_SAFETY",
			Summary:        "Unit-test-style local adversarial harness for RAG APIs and MCP servers (`aegisbox test --ai-safety`)",
			RemediationCmd: "aegisbox test --ai-safety --target http://127.0.0.1:8080/api/chat",
			WhyOneLiner:    "Runs deterministic local abuse probes and custom `--probes-file` packs, surfacing ONLY proven, reachable failures.",
			DeepWhy:        "Fires 12 built-in probes across indirect prompt injection, cross-tenant RAG bleed, path traversal, SSRF, MCP scope escalation, and secret egress canaries—plus up to 64 sanitized custom probes via `--probes-file` (<=256KB, os.OpenRoot). Every run writes a secret-redacted Flightdeck JSONL trace.",
			References:     []string{"OWASP-LLM01", "OWASP-LLM02", "docs/use-cases/03-unit-testing-ai-apps-locally.md"},
			ExitCode:       0,
		},
		"loopback": {
			Tool:           "aegisbox",
			Code:           "AEGISBOX_EXPLAIN_LOOPBACK",
			Summary:        "Strict loopback-pinned target validation (PANW Safe Harbor non-weaponization invariant)",
			RemediationCmd: "aegisbox test --ai-safety --target http://127.0.0.1:8080/api/chat",
			WhyOneLiner:    "Mechanically restricts AI-safety probing strictly to 127.0.0.1, ::1, localhost, or local STDIO processes.",
			DeepWhy:        "ValidateLocalTarget resolves DNS pre-dial, rejects public IPs, 0.0.0.0, cloud IMDS (169.254.169.254), IPv4-mapped IPv6, NAT64, DNS rebinding domains, and remote binaries, then pins the verified loopback IP inside net.Dialer.Control and blocks HTTP redirects leaving loopback.",
			References:     []string{"CWE-918", "docs/use-cases/03-unit-testing-ai-apps-locally.md"},
			ExitCode:       0,
		},
		"cow": {
			Tool:           "aegisbox",
			Code:           "AEGISBOX_EXPLAIN_COW",
			Summary:        "Copy-on-Write (CoW) ephemeral shadow workspaces & semantic diff review gate",
			RemediationCmd: "aegisbox diff",
			WhyOneLiner:    "Quarantines all agent file edits in a detached shadow copy so your real repo stays untouched until you approve.",
			DeepWhy:        "Aegisbox runs coding agents against detached Git worktrees / CoW overlays with .env and .git/hooks masked. Before `--apply` persists changes to the host repository, the Semantic Diff Auditor scans for trojaned postinstall hooks, binary implants, and path escapes.",
			References:     []string{"CWE-22", "docs/use-cases/02-cow-shadow-workspaces.md"},
			ExitCode:       0,
		},
		"degraded-local": {
			Tool:           "aegisbox",
			Code:           "AEGISBOX_EXPLAIN_DEGRADED_LOCAL",
			Summary:        "Explicit Tier-1 local containment opt-in (`--allow-degraded-local`) for headless CI without KVM",
			RemediationCmd: "aegisbox test --ai-safety --mcp-cmd \"node ./dist/mcp.js\" --allow-degraded-local",
			WhyOneLiner:    "Never silently downgrades microVM security; requires an explicit opt-in flag when /dev/kvm or Apple VZ is absent.",
			DeepWhy:        "On headless CI runners lacking nested hardware virtualization, Aegisbox refuses to silently fall back to host execution (invariant AEG-01). Passing `--allow-degraded-local` explicitly opts into isolated Tier-1 OS containment with sanitized ephemeral HOME and zero ambient host secrets.",
			References:     []string{"CWE-250", "README.md"},
			ExitCode:       0,
		},
	}

	entry, ok := explanations[topic]
	if !ok {
		ffe := &ux.FixForwardError{
			Tool:           "aegisbox",
			Code:           "AEGISBOX_EXPLAIN_UNKNOWN_TOPIC",
			Summary:        fmt.Sprintf("Unknown explain topic %q", topic),
			RemediationCmd: "aegisbox explain microvm",
			WhyOneLiner:    "Available topics: microvm, katas, ai-safety, loopback, cow, degraded-local.",
			DeepWhy:        "Run `aegisbox explain <topic>` with one of: microvm, katas, ai-safety, loopback, cow, degraded-local.",
			ExitCode:       1,
		}
		_ = ffe.Render(stderr, asJSON, true)
		return ffe
	}

	return entry.Render(stdout, asJSON, true)
}
