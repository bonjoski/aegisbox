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
```

---

## 2. Aegisbox vs. Airlock (Ecosystem Architecture)

Aegisbox is part of a complementary zero-trust security suite alongside **[Airlock](https://github.com/bonjoski/airlock)** and **[Argus](https://github.com/bonjoski/argus)**. Each tool targets a specific layer of developer and agent execution:

| Tool | Layer | Isolation Boundary | Startup | Ideal For |
| :--- | :--- | :--- | :--- | :--- |
| **[Argus](https://github.com/bonjoski/argus)** | Static Analysis Brain | Shell AST Inspection | <1ms | Pre-flight syntax parsing & package slopsquatting checks |
| **[Airlock](https://github.com/bonjoski/airlock)** | Workstation Sandbox | Kernel (macOS Seatbelt / Linux Landlock) | <15ms | CLI package shims (`npm install`, `pip install`, `cargo build`) |
| **[Aegisbox](https://github.com/bonjoski/aegisbox)** | MicroVM & Range Engine | Hypervisor (Apple VZ / Firecracker / Hyper-V) | ~100ms | Autonomous AI agent execution, red-team matrices & zero-escape |

### When to Use Which Tool

* **Choose [Airlock](https://github.com/bonjoski/airlock)** when you want transparent, sub-15ms process sandboxing for daily package manager workflows without the overhead of booting a virtual machine.
* **Choose [Aegisbox](https://github.com/bonjoski/aegisbox)** when executing untrusted autonomous AI agent loops (Claude, Gemini, Antigravity) that require complete hypervisor isolation, host-pinned firewalling, symlink traversal guards, and delayed diff weaponization auditing.

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

## 5. Running an AI Agent in the Sandbox

Aegisbox provides two primary patterns for executing autonomous AI agents safely:

1. **CLI Agent Wrapper Mode:** Run any CLI coding agent (Claude Code, Aider, Open Interpreter, or custom Python agent) directly inside the hardware microVM sandbox.
2. **IDE Agent MCP Mode:** Integrate with your IDE (Cursor, Claude Desktop, Antigravity) via Model Context Protocol so the agent routes all tool executions through Aegisbox.

```
                         HOW AGENT CONFINEMENT WORKS

      [ Mode 1: CLI Agent Wrapper ]             [ Mode 2: IDE Agent (MCP) ]
    (Claude Code, Aider, OpenDevin)         (Cursor, Claude Desktop, Antigravity)
                  │                                           │
                  ▼                                           ▼
      ┌───────────────────────┐                   ┌───────────────────────┐
      │ aegisbox exec ...     │                   │  IDE Agent Prompt     │
      └───────────┬───────────┘                   └───────────┬───────────┘
                  │                                           │ calls aegisbox_exec
                  ▼                                           ▼
      ┌───────────────────────────────────────────────────────────────────┐
      │                      AEGISBOX SANDBOX BARRIER                     │
      │                                                                   │
      │  1. Ephemeral Worktree: Detached Git clone (host repo untouched). │
      │  2. Secret Masking: .env, ~/.ssh hidden; synthetic env provided.  │
      │  3. Hardware MicroVM: Code runs inside isolated kernel / vsock.   │
      │  4. SafePath Guard: Traps symlink escapes and path traversals.    │
      │  5. Packet Filter: Egress pinned to host IP or total airgap.      │
      └─────────────────────────────────┬─────────────────────────────────┘
                                        │
                                        ▼
      ┌───────────────────────────────────────────────────────────────────┐
      │                     DELTA REVIEW & COMMIT GATE                    │
      │                                                                   │
      │  • File mutations are held in quarantine (never auto-applied).     │
      │  • Inspect with `aegisbox diff`.                                  │
      │  • Semantic Diff Auditor blocks trojaned postinstall / git hooks. │
      │  • Pass `--apply` to persist approved code back to host.          │
      └───────────────────────────────────────────────────────────────────┘
```

---

### Mode 1: CLI Agent Wrapper (Claude Code, Aider, Python Agents)

Wrap your agent's command with `aegisbox exec`. Aegisbox isolates the entire agent process, intercepts all filesystem writes, and blocks host secret theft:

```bash
# 1. Run Claude Code inside a microVM shadow sandbox
aegisbox exec --engine=microvm "claude --dangerously-skip-permissions"

# 2. Run Aider in an isolated Git worktree
aegisbox exec --engine=microvm "aider --yes"

# 3. Run a custom Python / LangChain / AutoGPT agent
aegisbox exec --engine=microvm "python3 agent.py"

# 4. Enforce strict network airgap (no outbound traffic, DNS sinkholed)
aegisbox exec --airgap --engine=microvm "python3 agent.py"
```

#### What happens during execution:
1. **Workspace Shadowing:** Aegisbox creates an ephemeral Git worktree at `~/.aegisbox/sessions/<session-id>`.
2. **Secret Shielding:** Real host `.env`, `.env.local`, and `.git/hooks` are masked. Synthetic dummy keys (`API_KEY=sk-dummy-test-0000`) are provided so SDKs don't crash.
3. **VM Isolation:** The agent and any child processes execute inside the Apple VZ / Firecracker microVM.
4. **Host Protection:** When the agent finishes, the host workspace is untouched. Changes remain quarantined in the session directory.

#### Reviewing & applying agent changes:
```bash
# Review quarantined diff
aegisbox diff

# Persist approved changes back to host repository
aegisbox exec --apply "claude"
```
*(If the agent planted trojan hooks like a malicious `package.json` `postinstall` or `.gitmodules` backdoor, the Semantic Diff Auditor will automatically block the apply.)*

---

### Providing Credentials to the Sandbox from Locksmith

By default, Aegisbox aggressively strips the host environment to ensure untrusted agents cannot read ambient cloud credentials, SSH keys, or `.env` files. When an agent genuinely requires an API token (such as `ANTHROPIC_API_KEY`), Aegisbox allows the host operator to pass designated environment variables across the sandbox barrier without exposing secrets on the command line.

#### Security Invariants:
* **Host-Only Locksmith Isolation:** Locksmith runs **exclusively on the host** to interface with the macOS Secure Enclave and Touch ID. The sandbox and the AI agent **never have access to Locksmith**, cannot execute Locksmith commands, and cannot request secrets.
* **Zero Secrets in `argv`:** Secret values are **never passed as command-line arguments** (preventing exposure in `ps aux`, process tables, and `.zsh_history`). Only variable *names* (keys) cross the barrier via `--allow-env`. Passing any `=` or value to `--allow-env` is rejected as an immediate security violation.
* **Zero-Disk Persistence:** Injected credentials exist *strictly in-memory* within the child process environment. They are never written to `.env.synthetic` or saved to the shadow worktree filesystem.
* **Automatic Console Redaction:** If an agent attempts to echo or dump an allowed variable (`echo $ANTHROPIC_API_KEY`), Aegisbox's `TerminalSanitizer` automatically intercepts stdout/stderr streams and replaces the secret with `[REDACTED_SECRET]`.

#### Usage Patterns:

**1. CLI Agent Execution (`locksmith run`):**
Use Locksmith's native runner on the host and specify which variable names Aegisbox should forward into the sandbox:
```bash
# Touch ID runs on the host; secret is passed purely in host-to-sandbox process memory
locksmith run -- aegisbox exec --allow-env ANTHROPIC_API_KEY "claude --dangerously-skip-permissions"
```

To forward multiple variables:
```bash
locksmith run -- aegisbox exec --allow-env ANTHROPIC_API_KEY,OPENAI_API_KEY "python3 agent.py"
```

**2. Host Environment Variable Allowlist (`AEGISBOX_ALLOW_ENV`):**
You can also set the allowlist via an environment variable on the host:
```bash
export AEGISBOX_ALLOW_ENV="ANTHROPIC_API_KEY,OPENAI_API_KEY"
locksmith run -- aegisbox exec "python3 agent.py"
```

---

### Mode 2: IDE Agent Tool-Calling via MCP (Cursor, Claude Desktop, Antigravity)

If your agent runs inside an IDE, configure Aegisbox as a Model Context Protocol (MCP) server. When the agent wants to execute shell commands, read files, or run tests, it executes them inside Aegisbox instead of on your raw host machine.

The AI agent in the IDE has **no direct access to credentials** and cannot request secrets from Locksmith. To provide API keys to sandboxed tool executions, wrap the MCP server invocation with `locksmith run` in your IDE config:

#### Configuration:

**Cursor (`.cursor/mcp.json`):**
```json
{
  "mcpServers": {
    "aegisbox": {
      "command": "locksmith",
      "args": ["run", "--", "aegisbox", "mcp"],
      "env": {
        "AEGISBOX_ALLOW_ENV": "ANTHROPIC_API_KEY,OPENAI_API_KEY"
      }
    }
  }
}
```

**Claude Desktop (`claude_desktop_config.json`):**
```json
{
  "mcpServers": {
    "aegisbox": {
      "command": "locksmith",
      "args": ["run", "--", "aegisbox", "mcp"],
      "env": {
        "AEGISBOX_ALLOW_ENV": "ANTHROPIC_API_KEY,OPENAI_API_KEY"
      }
    }
  }
}
```

#### Tools Provided to the Agent:
| Tool | Description |
| :--- | :--- |
| `aegisbox_exec(command, apply)` | Executes a shell command inside an ephemeral shadow worktree with secret masking and diff capture. |
| `aegisbox_vet(command)` | Pre-flight AST audit and hallucinated package slopsquatting check before execution. |
| `aegisbox_diff()` | Inspects quarantined workspace file changes. |

---

### Mode 3: Batch Multi-Agent Evaluation & Red-Teaming (`aegisbox matrix`)

To benchmark multiple agent prompts, jailbreak payloads, or coding tasks across parallel isolated workspaces:

```bash
# Run 4 parallel isolated shadow sandboxes against an evaluation manifest
aegisbox matrix --manifest test/adversarial/matrix_adversarial_campaign.json --concurrency=4
```
Aegisbox executes each task in an independent, detached worktree, checks for policy violations, and produces a structured safety scorecard.

---

### Monitoring Live Agent Execution (`aegisbox monitor`)

While an agent is executing in another terminal tab or IDE, launch the real-time TUI dashboard to observe resource usage and security events:

```bash
aegisbox monitor --demo
```
- **Real-Time Gauges:** Memory headroom, active PID count, and process limits.
- **Firewall State:** Pinned egress IP/port and armed canary tripwires.
- **Live Audit Stream:** Displays blocked reverse shells, masked secret accesses, and DNS queries in real time.

---

### Enforcing Sandbox-Only Execution (Locking Down Frontier Agents)

If you have a high-risk model or script (e.g. `mythos`, autonomous red-team agents) and want to guarantee that it **can only ever run inside Aegisbox** and never accidentally on your bare host machine:

#### 1. Self-Wrapping Script Pattern (Auto-Diversion)
Add this guard at the very top of your launcher script. If run directly on the host, it automatically diverts itself into Aegisbox:
```bash
#!/usr/bin/env bash
set -euo pipefail

# Invariant: Divert to Aegisbox if not already inside sandbox
if [ -z "${AEGISBOX_SANDBOX:-}" ]; then
  echo "🛡️  Host execution detected. Diverting into Aegisbox MicroVM..."
  exec aegisbox exec --engine=microvm "$0" "$@"
fi

# Real agent launch logic runs here (inside microVM)
python3 -m mythos.runner "$@"
```

#### 2. Strict Zero-Trust Guard (Hard Refusal)
Aegisbox injects `AEGISBOX_SANDBOX=1` and `AEGISBOX_GUEST_ACTIVE=1` into the microVM guest environment while stripping all host environment variables. You can hard-code your agent to refuse execution outside Aegisbox:

**In Python:**
```python
import os, sys

if not os.environ.get("AEGISBOX_SANDBOX") or not os.environ.get("AEGISBOX_GUEST_ACTIVE"):
    print("🚨 ACCESS DENIED: Agent cannot run outside Aegisbox sandbox!", file=sys.stderr)
    sys.exit(126)
```

**In Bash:**
```bash
if [ -z "${AEGISBOX_SANDBOX:-}" ]; then
  echo "🚨 ACCESS DENIED: Agent cannot run outside Aegisbox sandbox!" >&2
  exit 126
fi
```

#### 3. Transparent System Shim
To guarantee that typing your agent command anywhere on the system always spawns inside Aegisbox:
```bash
# Point a global wrapper in /usr/local/bin to aegisbox
sudo tee /usr/local/bin/mythos << 'EOF'
#!/usr/bin/env bash
exec aegisbox exec --engine=microvm "$HOME/.aegisbox/internal/mythos-core" "$@"
EOF
sudo chmod +x /usr/local/bin/mythos
```

---

## 6. CLI Command Reference

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
