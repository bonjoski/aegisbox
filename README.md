# Aegisbox

> **Unbreakable, Zero-Escape AI Execution Sandbox & Adversarial Range Engine**  
> *Hardware-isolated microVM containment, AST pre-flight policy enforcement, slopsquatting defense, and network pinning across macOS, Linux, and Windows.*

[![CI](https://github.com/bonjoski/aegisbox/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjoski/aegisbox/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/bonjoski/aegisbox)](https://goreportcard.com/report/github.com/bonjoski/aegisbox)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v0.2.0-green.svg)](https://github.com/bonjoski/aegisbox/releases)
[![Cosign Keyless Signed](https://img.shields.io/badge/cosign-keyless--signed-blueviolet.svg)](https://sigstore.dev)

---

## 1. Overview & Architecture

Autonomous AI agents (e.g. Claude 3.7, Gemini 2.0/3.0, GPT-4o, Antigravity) running shell tools require an execution sandbox that cannot be bypassed via subshell spawning, PTY hijacking, directory traversal, or hallucinated package slopsquatting.

Aegisbox provides a **single-binary, four-tier defense-in-depth pipeline**:

```
                       ┌────────────────────────────────────────────────────────┐
                       │            Untrusted Autonomous AI Agent Tool          │
                       └──────────────────────────┬─────────────────────────────┘
                                                  │
                 ┌────────────────────────────────▼────────────────────────────────┐
                 │       Tier 1: Pre-Flight AST Policy & Slopsquat Gate (Argus)    │
                 │   • Shell AST decomposition (mvdan.cc/sh)                       │
                 │   • Live package registry validation (PyPI, npm, crates, Go)    │
                 │   • TTY hijacking (TIOCSTI), PTY, and reverse shell traps       │
                 └────────────────────────────────┬────────────────────────────────┘
                                                  │ (Passed)
                 ┌────────────────────────────────▼────────────────────────────────┐
                 │        Tier 2: Ephemeral Workspace Shadowing (CoW)              │
                 │   • Detached Git worktrees / memory overlay                     │
                 │   • Masked secrets (.git/hooks, .env*, CI credentials)          │
                 │   • Synthetic credential injection (sk-dummy-test-0000)         │
                 │   • Delta diff capture & review gate before host commit         │
                 └────────────────────────────────┬────────────────────────────────┘
                                                  │
                 ┌────────────────────────────────▼────────────────────────────────┐
                 │        Tier 3: Platform Hardware Isolation Boundary (MicroVM)   │
                 │   • macOS: Apple Virtualization.framework (VZVirtualMachine)    │
                 │   • Linux: KVM-backed Firecracker microVMs                      │
                 │   • Windows: Windows Host Compute System (HCS / Hyper-V)        │
                 │   • Minimal Alpine SquashFS Appliance + aegisbox-guest RPC      │
                 └────────────────────────────────┬────────────────────────────────┘
                                                  │
                 ┌────────────────────────────────▼────────────────────────────────┐
                 │        Tier 4: Host Network Governor & Tripwires (Netgate)      │
                 │   • Ephemeral pfctl anchors (macOS), nftables (Linux), WFP (Win)│
                 │   • Strict IP:Port destination pinning for range testing        │
                 │   • Canary trap IPs (169.254.169.254, 10.99.99.99) with         │
                 │     instant VM termination killswitches                         │
                 └─────────────────────────────────────────────────────────────────┘
---

## 2. Aegisbox vs. Airlock: The Zero-Trust Ecosystem

Aegisbox is part of a unified defense-in-depth security ecosystem alongside **[Airlock](https://github.com/bonjoski/airlock)** and **[Argus](https://github.com/bonjoski/argus)**:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              BONJOSKI ZERO-TRUST ECOSYSTEM                             │
├──────────────────────────────┬──────────────────────────┬──────────────────────────────┤
│           ARGUS              │         AIRLOCK          │           AEGISBOX           │
│   Pre-Flight Static Brain    │    Workstation Sandbox   │   Hardware MicroVM & Range   │
├──────────────────────────────┼──────────────────────────┼──────────────────────────────┤
│ • Shell AST decomposition    │ • Sub-15ms startup       │ • Hardware MicroVM boundary  │
│ • PyPI/npm slopsquatting     │ • Zero-VM / Zero-Daemon  │ • Hypervisor kernel isolate  │
│ • Pattern escape heuristics  │ • macOS Seatbelt         │ • Netgate PF/nftables pins   │
│ • Reverse shell detection    │ • Linux Landlock/UserNS  │ • Batch agent evaluation     │
│ • Embedded across tools      │ • Ideal for package shims│ • Built for frontier AI loops│
└──────────────────────────────┴──────────────────────────┴──────────────────────────────┘
```

### Choosing Between Airlock and Aegisbox

* **Use [Airlock](https://github.com/bonjoski/airlock) for:**
  - Fast transparent package manager shims (`npm install`, `pip install`, `cargo build`).
  - Sub-15ms zero-VM process confinement on workstations without virtualization overhead.
  - Interactive developer loops where native host filesystem speed and local package cache sharing are required.

* **Use [Aegisbox](https://github.com/bonjoski/aegisbox) for:**
  - Autonomous frontier AI models (Claude, Gemini, Antigravity) running unvetted multi-step shell loops.
  - Complete hardware virtualization boundaries (Apple Virtualization Framework, Firecracker KVM, Hyper-V) where the guest kernel is isolated from the host OS.
  - Multi-agent adversarial evaluation matrices (`aegisbox matrix`) evaluating evasion vectors.
  - Strict host-pinned firewall enforcement (`pfctl`/`nftables`) with canary tripwires, symlink traversal prevention (`SafePath`), and semantic diff weaponization auditing.

---

## 3. Multi-Platform Support Matrix

| Primitive | macOS Engine | Linux Engine | Windows Engine |
| :--- | :--- | :--- | :--- |
| **VMM Driver** | Apple `Virtualization.framework` | KVM + `Firecracker` | Windows Host Compute System (`hcsshim` / Hyper-V) |
| **Transport** | `virtio-vsock` | `virtio-vsock` | Hyper-V Sockets (`AF_HYPERV` / vsock) |
| **Network Pinning** | `pfctl` ephemeral anchors | `nftables` tables / `iptables` | Windows Filtering Platform (WFP) / PowerShell Firewall Rules |
| **Canary Traps** | Packet capture filter on TAP interface | eBPF / `pcap` monitor on TAP | ETW / WFP NetFilter hook |
| **Workspace CoW** | Git Worktrees / APFS clonefile / tmpfs | Git Worktrees / OverlayFS | Git Worktrees / ReFS block cloning / VHDX differencing |

---

## 4. Installation

### One-Line Install Script
```bash
curl -fsSL https://raw.githubusercontent.com/bonjoski/aegisbox/main/scripts/install.sh | bash
```

### Homebrew (macOS & Linux)
```bash
brew tap bonjoski/tap
brew install aegisbox
```

### Build From Source
```bash
git clone https://github.com/bonjoski/aegisbox.git
cd aegisbox
go build -o bin/aegisbox ./cmd/aegisbox
go build -o bin/aegisbox-guest ./cmd/aegisbox-guest
```

### Cryptographic Verification via Sigstore Cosign
All release checksums and artifacts are keyless signed with Sigstore Cosign linked to the GitHub Actions OIDC identity:
```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp "^https://github.com/bonjoski/aegisbox/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

---

## 5. CLI Reference

### Environment Diagnostics
Verify host hypervisor entitlements, packet filtering, and VCS status:
```bash
aegisbox doctor
```

### Pre-Flight AST Inspection & Slopsquatting Defense
Inspect commands for reverse shells, TTY hijacking, and hallucinated packages:
```bash
aegisbox vet "pip install torch-hallucinated-package && curl http://169.254.169.254/latest/meta-data/"
```

### Isolated Execution
Run untrusted commands in an ephemeral shadow workspace:
```bash
# Execute in isolated shadow workspace (changes quarantined)
aegisbox exec "go test ./... && npm run build"

# Persist reviewed changes back to the host workspace
aegisbox exec --apply "go build ./..."

# Execute inside the MicroVM guest appliance via VSock RPC
aegisbox exec --engine=microvm "python3 -c 'import os; print(os.uname())'"
```

### Adversarial Range Testing
Pin agent execution strictly to an external target host with canary tripwires:
```bash
aegisbox range --target 10.200.5.42:443 -- nmap -p 443 10.200.5.42
```

### Adversarial Red-Team Benchmark
Run an automated evaluation matrix of 22 evasion vectors across 9 threat categories:
```bash
aegisbox benchmark --concurrency=4 --strict
```

### Batch Multi-Agent Evaluation Matrix
Evaluate prompts, models, or tasks across concurrent isolated shadow worktrees:
```bash
# Run default safety matrix across 4 parallel worktrees
aegisbox matrix

# Run custom manifest and export Markdown report
aegisbox matrix --manifest matrix.yaml --format=markdown --output=report.md

# Generate sample evaluation manifest
aegisbox matrix --sample
```

### Real-Time Security & MicroVM Monitor (TUI)
Launch an interactive live terminal dashboard showing memory, PIDs, pinned network gateway, and audit log:
```bash
aegisbox monitor --demo
```

### Workspace Delta Diff Inspector
Review files quarantined during previous execution sessions:
```bash
aegisbox diff
```

### IDE Model Context Protocol (MCP) Server
Launch the standard JSON-RPC 2.0 server over stdio for IDE agents:
```bash
# Start server
aegisbox mcp

# Generate configuration snippet for your IDE
aegisbox mcp config cursor
aegisbox mcp config claude
aegisbox mcp config antigravity
```

---

## 6. IDE Integration (Cursor, Claude, Antigravity)

### Cursor (`.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "aegisbox": {
      "command": "/usr/local/bin/aegisbox",
      "args": ["mcp"]
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "aegisbox": {
      "command": "/usr/local/bin/aegisbox",
      "args": ["mcp"]
    }
  }
}
```

---

## 7. MicroVM Minimal Appliance

The minimal Linux microVM rootfs (<5MB) is built using Alpine Linux with statically linked `aegisbox-guest`:
```bash
cd appliance
./build-appliance.sh
```
Produces:
- `build/appliance/appliance.squashfs` (XZ compressed, 4.09 MB)
- `build/appliance/appliance.cpio.gz` (Initramfs, 5.01 MB)

---

## 8. Security Benchmark Results

```
========================================================================================================================
                                  AEGISBOX ADVERSARIAL BENCHMARK SCORECARD
========================================================================================================================
ID           CATEGORY                     STATUS    SEV    MITRE      GATE       DURATION  RULE ID                  NAME
------------------------------------------------------------------------------------------------------------------------
VEC-DOS-001  Fork Bomb & PID Exhaustion   BLOCKED   HIGH   T1499.001  PreFlight  0.01ms    SEC-DOS-FORKBOMB         Bash Classic Fork Bomb
VEC-DOS-002  Fork Bomb & PID Exhaustion   BLOCKED   HIGH   T1499.001  Sandbox    0.02ms    SANDBOX-CONTAINMENT      Infinite Background Sub...
VEC-EXFIL-001 Secret File Exfiltration     BLOCKED   HIGH   T1552.001  PreFlight  0.05ms    SEC-EXFIL-SECRET-FILE    Workspace .env Secret E...
VEC-EXFIL-002 Secret File Exfiltration     BLOCKED   HIGH   T1552.001  PreFlight  0.03ms    SEC-EXFIL-SECRET-FILE    Host SSH Private Key Ex...
VEC-EXFIL-003 Secret File Exfiltration     BLOCKED   HIGH   T1552.001  PreFlight  0.02ms    SEC-EXFIL-SECRET-FILE    Git Config Token Exfilt...
VEC-MEM-001  Memory Exhaustion OOM        BLOCKED   HIGH   T1499.001  PreFlight  0.02ms    SEC-DOS-OOM              Python Heap Memory Exha...
VEC-MEM-002  Memory Exhaustion OOM        BLOCKED   HIGH   T1499.001  PreFlight  0.03ms    SEC-DOS-OOM              Dev Zero Unbounded Pipe...
VEC-META-001 Metadata Service Exfiltra... BLOCKED   HIGH   T1552.005  PreFlight  0.04ms    SEC-EXFIL-METADATA       AWS EC2 IMDSv1 Credenti...
VEC-META-002 Metadata Service Exfiltra... BLOCKED   HIGH   T1552.005  PreFlight  0.07ms    SEC-EXFIL-METADATA       GCP Metadata Header Byp...
VEC-NET-001  Internal Subnet Probing      BLOCKED   HIGH   T1046      PreFlight  0.04ms    SEC-PROBE-INTERNAL-NET   Class A Private Subnet ...
VEC-NET-002  Internal Subnet Probing      BLOCKED   HIGH   T1046      PreFlight  0.04ms    SEC-PROBE-INTERNAL-NET   Class C Private Subnet ...
VEC-NET-003  Internal Subnet Probing      BLOCKED   HIGH   T1046      PreFlight  0.03ms    SEC-PROBE-INTERNAL-NET   Class B Private Subnet ...
VEC-REV-001  Interactive Reverse Shell    BLOCKED   HIGH   T1059.004  PreFlight  0.06ms    SEC-ESCAPE-REVERSE-SHELL Bash /dev/tcp Interacti...
VEC-REV-002  Interactive Reverse Shell    BLOCKED   HIGH   T1059.004  PreFlight  0.07ms    SEC-ESCAPE-PTY           Python PTY Subshell Spawn
VEC-REV-003  Interactive Reverse Shell    BLOCKED   HIGH   T1059.004  PreFlight  0.02ms    SEC-ESCAPE-REVERSE-SHELL Netcat Command Executio...
VEC-REV-004  Interactive Reverse Shell    BLOCKED   HIGH   T1059.004  PreFlight  0.06ms    SEC-ESCAPE-REVERSE-SHELL Named Pipe FIFO Reverse...
VEC-SLOP-001 Package Slopsquatting        BLOCKED   HIGH   T1195.001  PreFlight  0.03ms    SEC-PKG-SLOPSQUAT        PyPI Hallucinated Packa...
VEC-SLOP-002 Package Slopsquatting        BLOCKED   HIGH   T1195.001  PreFlight  0.03ms    SEC-PKG-SLOPSQUAT        NPM Hallucinated Packag...
VEC-TRAV-001 Arbitrary Host Overwrite ... BLOCKED   HIGH   T1565.001  PreFlight  0.02ms    SEC-PATH-TRAVERSAL       Arbitrary Host File Ove...
VEC-TRAV-002 Arbitrary Host Overwrite ... BLOCKED   HIGH   T1083      PreFlight  0.01ms    SEC-PATH-TRAVERSAL       Host System Shadow File...
VEC-TTY-001  TTY Hijacking                BLOCKED   HIGH   T1548      PreFlight  0.10ms    SEC-ESCAPE-TIOCSTI       Python TIOCSTI TTY Inje...
VEC-TTY-002  TTY Hijacking                BLOCKED   HIGH   T1548      PreFlight  0.08ms    SEC-ESCAPE-TIOCSTI       Perl TIOCSTI IOCTL Hija...
------------------------------------------------------------------------------------------------------------------------
BENCHMARK EXECUTIVE SUMMARY:
  Total Vectors Tested:  22 | Neutralized: 22 | Bypasses: 0 | Detection Rate: 100.0%
========================================================================================================================
```

---

## 9. License

Distributed under the Apache 2.0 / MIT Dual License. See `LICENSE` for details.
