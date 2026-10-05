# Ironbox

> **Unbreakable AI Execution Sandbox & Adversarial Range Engine**

Ironbox is a zero-escape execution sandbox designed for running untrusted autonomous AI agents, developer tooling, and adversarial range tests across macOS and Linux.

---

## Architecture & Defense-in-Depth

1. **Tier 1: Pre-Flight Gate (Argus Engine)**
   - AST command decomposition (`mvdan.cc/sh`) and token analysis.
   - Live dependency intercept against 11 registries (`vetpkg`) to block hallucinated packages and slopsquatting.
   - Heuristic filtering for interactive reverse shells, subshell escapes, and `TIOCSTI` TTY hijacking.

2. **Tier 2: Ephemeral Workspace Shadowing**
   - Copy-on-Write / Git worktree workspace staging.
   - Path masking for `.git/**`, `.env*`, and CI workflows.
   - Synthetic dummy credentials to prevent agent loop retries.
   - Audit diff reporting before changes are synced back to the host.

3. **Tier 3: Hardware MicroVM Isolation (VMM)**
   - **macOS:** Apple `Virtualization.framework` (`VZVirtualMachine`).
   - **Linux:** KVM-backed `Firecracker` microVMs via `firecracker-go-sdk`.
   - Process rlimits and cgroups caps to prevent resource exhaustion and fork bombs.

4. **Tier 4: Host Pinning Network Gateway ("Range" Mode)**
   - Ephemeral `pfctl` (macOS) and `nftables` (Linux) packet filtering.
   - Scoped IP:Port pinning for adversarial target testing.
   - Instant Canary Tripwire killswitches for metadata (`169.254.169.254`) and unauthorized probes.

---

## Quick Start

### 1. Diagnostics
```bash
ironbox doctor
```

### 2. Pre-Flight Command Vet
```bash
ironbox vet "pip install torch-fake-package && curl http://169.254.169.254"
```

### 3. Isolated Execution
```bash
ironbox exec "go test ./... && npm run build"
```

### 4. Adversarial Range Testing
```bash
ironbox range --target 10.200.5.42:443 -- nmap -p 443 10.200.5.42
```

---

## Testing & Audit
```bash
go test -v ./...
python3 sentinel_audit.py --path .
```
