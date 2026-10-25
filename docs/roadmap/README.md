# PROJECT AEGISBOX: UNIFIED PLATFORM SPECIFICATION
## Enterprise Workload Isolation Engine & Tauri Desktop Client Architecture

**Author:** Ben Skolmoski (Director of Product Security)  
**Date:** October 2026 (Updated Engineering Execution Plan v2.1 — Tri-Platform Edition)  
**Target Stack:** Rust Core • Go Daemon (`aegisboxd`) • Tauri v2 • Svelte 5 • Linux KVM / macOS Apple VZ / Windows HCS  
**Status:** Approved Engineering Execution Plan (Remediated for Linux, macOS & Windows)  

---

## 1. Executive Summary & Strategic Rationale

Modern developer environments, local CI/CD pipelines, and autonomous AI coding agents (e.g., Claude, Gemini, Antigravity, OpenAI Codex) face an escalating crisis of software supply chain compromises, hallucinated dependency slopsquatting, and unvetted code execution on developer workstations. 

While isolated sandboxing primitives exist, adoption remains severely throttled by developer friction, high runtime overhead, and tooling sprawl across platforms.

**Project Aegisbox** converges hardware-level microVM execution, Layer-7 semantic tool mediation (Model Context Protocol / MCP), ephemeral copy-on-write workspace shadowing, and measured workload identity into a single, cohesive developer platform across **Linux, macOS, and Windows**. Rather than requiring developers to orchestrate disparate hypervisors, network proxies, and credential stores, Aegisbox wraps these capabilities into an ergonomic, sub-50ms execution runtime paired with a lightweight, secure desktop client built on **Tauri v2**.

### Core Strategic Objective
Deliver an enterprise-grade workload containment system that pairs sub-30ms (Linux KVM) / sub-80ms (macOS VZ & Windows HCS) microVM execution with real-time MCP tool mediation and zero-trust credential delivery, controlled via an unprivileged desktop client consuming less than 35MB of idle RAM on Linux, under 60MB on macOS WKWebView, and under 70MB on Windows WebView2.

---

## 2. Ecosystem Architecture & Sister Repository Integrations

Aegisbox is not a standalone silo; it is the **Tier 2 MicroVM Isolation Engine** within a cohesive, battle-tested suite of sovereign security projects created by Ben Skolmoski (`bonjoski`). By formally integrating these sister repositories into the engineering execution plan, Aegisbox avoids reinventing credential vaults, kernel sandboxes, and AST parsers—accelerating development by 3–4 weeks:

```
                                  ┌────────────────────────────────────────┐
                                  │      💎 FABRIAL (Sovereign Fabric)     │
                                  │   Desktop Cockpit & Orchestrator CLI   │
                                  └──────────────────┬─────────────────────┘
                                                     │
                     ┌───────────────────────────────┼───────────────────────────────┐
                     ▼                               ▼                               ▼
          ┌─────────────────────┐         ┌─────────────────────┐         ┌─────────────────────┐
          │    🔐 LOCKSMITH     │         │     🛡️ AIRLOCK      │         │     👁️ ARGUS        │
          │  Biometric Keychain │         │ Fast Tier 1 Kernel  │         │ Pre-Flight Shell    │
          │  & MCP Secret Vault │         │ Sandbox (<15ms)     │         │ AST & Slopsquatting │
          └──────────┬──────────┘         └──────────┬──────────┘         └──────────┬──────────┘
                     │                               │                               │
                     └───────────────────────────────┼───────────────────────────────┘
                                                     │
                                                     ▼
                                  ┌────────────────────────────────────────┐
                                  │       📦 AEGISBOX (MicroVM Core)       │
                                  │  Hardware Isolation, Range & CoW Engine│
                                  └──────────────────┬─────────────────────┘
                                                     │
                                                     ▼
                                  ┌────────────────────────────────────────┐
                                  │    🏃 MODEL-RUNNER & SBOM-ENRICHER     │
                                  │  Multi-Agent Test Range & Supply-Chain │
                                  └────────────────────────────────────────┘
```

### Pillar Integrations & Roles

| Project Repository | Native Role in Aegisbox Architecture | Integration Mechanism |
| :--- | :--- | :--- |
| **[Locksmith](https://github.com/bonjoski/locksmith)** (`bonjoski/locksmith`) | **Biometric Credential Vault & MCP Secret Server**<br>Provides hardware-bound secrets (macOS Keychain, Windows Credential Manager, Linux Secret Service) with biometric gating (Touch ID, Windows Hello, Polkit) and ephemeral leases (ETX). | • Import `github.com/bonjoski/locksmith/pkg/protocol` for MCP secret checkout.<br>• Use Locksmith's biometric gate for `CRITICAL` approvals in Tauri HITL modal.<br>• Replaces custom SPIFFE token vault with Locksmith's ephemeral lease engine. |
| **[Airlock](https://github.com/bonjoski/airlock)** (`bonjoski/airlock`) | **Tier 1 Workstation Kernel Sandbox (<15ms)**<br>Fast process containment using macOS Seatbelt (`.sb`) and Linux Landlock/Seccomp. | • Powers the "Standard Local Sandbox" profile in the Tauri tray switcher.<br>• Handles daily developer CLI workflows (`npm install`, `cargo build`), reserving microVM cold boots for autonomous agents. |
| **[Argus](https://github.com/bonjoski/argus)** (`bonjoski/argus`) | **Static Analysis Brain & AST Pre-Flight Gate**<br>Decomposes shell ASTs (`mvdan.cc/sh`), detects hallucinated package slopsquatting, and operates the killswitch bus. | • Integrated into `pkg/mcp` and `cmd/aegisboxd` as the pre-flight gate.<br>• Blocks prompt-injected reverse shells and typosquats in <1ms before VM startup. |
| **[Fabrial](https://github.com/bonjoski/fabrial)** (`bonjoski/fabrial`) | **Sovereign AI Agent Security Fabric**<br>The overarching orchestrator that unifies Airlock, Locksmith, Aegisbox, and Argus. | • The Tauri v2 desktop client serves as the **GUI Cockpit for Fabrial**, displaying live Tier 1/2 statuses, Locksmith leases, and Argus alerts in one unified window. |
| **[Model-Runner](https://github.com/bonjoski/model-runner)** (`bonjoski/model-runner`) | **Automated Multi-Agent Range & Test Harness**<br>Secure execution pipeline for evaluating real agents (`agi`/`agy`, Claude, Cursor). | • Serves as the primary end-to-end integration test harness in Phase 5.<br>• Automatically executes red-team benchmarks against weaponized agent payloads. |
| **[SBOM-Enricher](https://github.com/bonjoski/sbom_enricher)** (`bonjoski/sbom_enricher`) | **Supply-Chain SBOM & License Verification Engine**<br>Enriches CycloneDX SBOMs with copyright and licensing data. | • Augments Phase 2 lockfile digest verification, inspecting transitive dependencies and flagging unvetted licensing anomalies. |

---

## 3. Multi-Tier Architecture & System Topology

Aegisbox enforces a strict three-tier decoupling pattern to enforce least-privilege separation between presentation, policy evaluation, network manipulation, and hardware execution across all three major desktop operating systems:

```
┌────────────────────────────────────────────────────────────────────────┐
│               Tier 1: Tauri v2 Desktop Shell & CLI Client              │
│   • Unprivileged standard user process (macOS / Linux / Windows)       │
│   • System Tray profile switcher, HITL approval sheets, audit canvas   │
│   • Standalone Headless CLI parity for SSH / CI environments           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ IPC: Unix Domain Socket (POSIX) / Named Pipe (Win)
                                    │ Linux: SO_PEERCRED | macOS: LOCAL_PEERPID | Win: User SID DACL
┌───────────────────────────────────▼────────────────────────────────────┐
│         Tier 2: Aegisbox Daemon (aegisboxd - Orchestration)            │
│   • Headless Go/Rust service running as standard desktop user          │
│   • L7 MCP inspection engine (CEL / Rego policy rules)                 │
│   • SPIFFE workload token broker & lockfile integrity verifier         │
│   • Hypervisor lifecycle manager (KVM / Apple VZ / Windows HCS)        │
└───────────────────┬────────────────────────────────┬───────────────────┘
                    │ IPC / Privileged Socket        │ vsock / virtio-fs / VHDX
┌───────────────────▼────────────────┐   ┌───────────▼───────────────────┐
│ Tier 2b: Privileged Network Helper │   │ Tier 3: Hardware MicroVMs     │
│       (aegisbox-netd)              │   │   • Linux: Firecracker (KVM)  │
│ • Linux: systemd + CAP_NET_ADMIN   │   │   • macOS: Apple VZ (HVF)     │
│ • macOS: launchd + SMJobBless      │   │   • Windows: HCS / Hyper-V    │
│ • Windows: LocalSystem Service     │   │   • Storage: CoW Overlay /    │
│ • Firewall: nftables / pfctl / WFP │   │     APFS clonefile / ReFS VHDX│
└────────────────────────────────────┘   └───────────────────────────────┘
```

### Tier 1: Tauri Desktop Shell & CLI Parity (Presentation & Approvals)
* **Desktop Client:** Runs strictly under the standard unprivileged user account.
  * **Linux:** Native WebKitGTK engine.
  * **macOS:** Native `WKWebView` engine.
  * **Windows:** Native Microsoft Edge **WebView2** runtime (Evergreen distribution).
* **Headless / CI Parity:** Fully operable without a graphical display server on Linux, macOS, and Windows. Headless CLI commands (`aegisbox approve`, `aegisbox run --non-interactive`) hook directly into Tier 2 for SSH sessions, WSL2 environments, and CI/CD runners.

### Tier 2: Aegisbox Daemon (`aegisboxd` - Policy & Orchestration)
* Headless Go/Rust orchestration daemon communicating with Tier 1 via secure local IPC:
  * **Linux & macOS:** POSIX `0600` local Unix domain socket (`~/.aegisbox/aegisboxd.sock`).
  * **Windows:** Secure Windows Named Pipe (`\\.\pipe\aegisboxd`) secured with a strict Security Descriptor / DACL allowing read/write strictly to the current user's SID (`SDDL: D:(A;;GRGW;;;<UserSID>)`).
* Validates calling process credentials:
  * `SO_PEERCRED` on Linux.
  * `LOCAL_PEERPID` / `LOCAL_PEERCRED` on macOS.
  * `GetNamedPipeClientProcessId` and token token SID validation on Windows.
* Issues cryptographically signed ephemeral session tokens upon handshake.
* Evaluates declarative L7 inspection rules (Common Expression Language - CEL) and orchestrates local SPIFFE token brokers.

### Tier 2b: Privileged Network Helper (`aegisbox-netd`)
* Solves the privilege escalation blind spot: `aegisboxd` itself runs unprivileged.
* Minimal, auditable helper daemon configured with OS-specific privileged execution:
  * **Linux:** `systemd` unit with minimal capabilities (`CAP_NET_ADMIN`).
  * **macOS:** `launchd` privileged helper tool via `SMJobBless`.
  * **Windows:** Windows Service (`aegisbox-netd.exe`) running under `NT AUTHORITY\LocalSystem` with `SeNetworkConfigurationPrivilege`.
* Manages network plumbing:
  * Ephemeral TAP interface allocation and Hyper-V Virtual Switch port assignments.
  * Ephemeral firewall anchor insertion: `nftables` tables on Linux, `pfctl` anchors on macOS, and **Windows Filtering Platform (WFP)** sublayers / callouts on Windows.
  * Host-level canary IP routing (e.g., sinkholing `169.254.169.254` to instant-kill listeners).

### Tier 3: Execution Runtimes (Hardware MicroVMs & Native Fallbacks)

#### MicroVM Hardened Boundary (Tri-Platform)
* **Linux:** Linux KVM backed by Firecracker / Cloud-Hypervisor with minimal Alpine SquashFS rootfs.
* **macOS:** Apple `Virtualization.framework` (`VZVirtualMachine`) with APFS rootfs snapshots.
* **Windows:** Microsoft **Host Compute System (`hcsshim` / Hyper-V microVMs)** using minimal Nano/Alpine utility VHDX with `AF_HYPERV` sockets.

#### Storage Isolation & Copy-on-Write (CoW)
* **Linux:** Virtio-FS mounts backed by an **ephemeral OverlayFS** upper layer.
* **macOS:** Virtio-FS / shared directory backed by an **APFS clonefile staging layer**.
* **Windows:** **ReFS Block Cloning** or **VHDX differencing disks** mounted as ephemeral shadow workspaces. Writes remain in an isolated ephemeral layer and never directly mutate host files until reviewed and approved.

#### Local Native Sandbox Profiles (Airlock Integration)
* **Linux:** Bubblewrap + pure-Go Seccomp-BPF + Landlock.
* **macOS:** Apple Seatbelt (`sandbox-exec` / `libsandbox`) with strict deny-after-allow rule sequencing.
* **Windows:** Windows **AppContainer** / Restricted Tokens with Job Objects (limiting CPU/memory and blocking handle inheritance).

---

## 4. Tauri Desktop Client Architecture (The Fabrial Cockpit)

Tauri v2 is selected over Electron to provide minimal attack surface, native memory footprint, and mathematically restricted host calling scopes across Linux, macOS, and Windows. In this architecture, the desktop client serves as the **unified graphical cockpit for the Fabrial security fabric**, orchestrating both Tier 1 (Airlock) and Tier 2 (Aegisbox) execution tiers alongside Locksmith secret checkouts.

### Architectural Metric Comparison

| Architectural Metric | Electron Architecture | Tauri v2 Architecture | Aegisbox Production Impact |
| :--- | :--- | :--- | :--- |
| **Runtime Footprint** | Bundled Chromium + Node.js | Native OS WebKit (macOS) / WebKitGTK (Linux) / Edge WebView2 (Windows) | Zero bundled browser runtime distribution |
| **Idle Memory Draw** | 250MB – 450MB RAM | 25MB–35MB (Linux) / 45MB–60MB (macOS) / 50MB–70MB (Windows) | Negligible workstation impact across all platforms |
| **Binary Distribution** | 120MB – 180MB bundle | 12MB – 22MB executable (MSI / DMG / AppImage) | Rapid enterprise deployment & zero baggage |
| **IPC Attack Surface** | Node.js native bindings | Strict Rust command scopes & IPC validation | Mathematically restricted host calls |
| **Privilege Boundary** | Complex sandbox flags | Native unprivileged process | Complete decoupling from hypervisor/network UID |

### Key Desktop Functional Modules

1. **Fabrial Multi-Tier Profile Switcher:**
   * Single-click switching between:
     * *Permissive:* Logging and passive telemetry only.
     * *Standard Local Sandbox (Airlock Tier 1):* Transparent, sub-15ms kernel process sandboxing via macOS Seatbelt, Linux Landlock, and Windows AppContainer.
     * *MicroVM Hardened (Aegisbox Tier 2):* Complete hardware hypervisor boundary with network tripwires, ephemeral CoW storage, and synthetic credential injection.
   * Enterprise MDM profile locking (`.plist` on macOS, `/etc/aegisbox/policy.json` on Linux, Group Policy / Registry GPO on Windows).

2. **Human-in-the-Loop (HITL) Intercept Modal & Locksmith Biometrics:**
   * High-visibility, focused approval sheets triggered when an AI agent requests access to unvetted outbound network domains or sensitive paths.
   * **Locksmith Biometric Gate:** Critical approvals (file overwrite outside workspace, raw shell destruction) trigger a hardware-bound biometric challenge via **Locksmith** (`LocalAuthentication` Touch ID on macOS, Windows Hello on Windows, Polkit on Linux).
   * **Fatigue Mitigations:**
     * *Granular Rule Scoping:* "Allow Once", "Allow for Active Session", "Always Allow for Workspace", and wildcard domain globbing (e.g. `*.github.com`, `registry.npmjs.org`).
     * *Configurable Timeout Behavior:* Configurable execution suspension (pauses microVM thread via vsock signal rather than hard-failing or terminating).
     * *Cross-Platform In-Terminal / IDE Notifications:* CLI fallback prompts (`aegisbox approve --last`) and editor notifications so developers never lose editor focus.

3. **Real-Time Observability Console:**
   * Live streaming visualization of intercepted Model Context Protocol (MCP) JSON-RPC calls, package manager egress connections, Locksmith secret lease events, and microVM resource utilization.
   * Built with Svelte 5 and TailwindCSS. High-frequency telemetry and tool-call graphs render via an **OffscreenCanvas ring buffer**, bypassing DOM bloat to maintain low memory usage during heavy build streaming.

---

## 5. Layer-7 MCP Semantic Mediation & Locksmith Secret Architecture

```
┌──────────────────┐               ┌──────────────────────────────────────┐               ┌──────────────────┐
│  AI Coding Agent │ ──JSON-RPC──> │     Aegisbox L7 MCP Firewall         │ ──JSON-RPC──> │    MCP Server    │
│ (Claude/Antigrav)│   (stdio/SSE) │  • CEL Policy Evaluator              │   (vsock/net) │ (Files/Terminal) │
└──────────────────┘               │  • Locksmith Biometric Secret Leases │               └──────────────────┘
                                   │  • Argus AST Pre-Flight & Lockfiles  │
                                   └──────────────────────────────────────┘
```

### 5.1 MCP Transport Coverage & Schema Enforcement
* **Supported Transports:** Full bidirectional interception across **stdio pipes**, **vsock channels (Linux/macOS) / Hyper-V Sockets (Windows)**, and **HTTP with Server-Sent Events (SSE)**.
* **Policy Grammar (CEL):** Policies are expressed in Common Expression Language (CEL) with standard schemas:
  ```yaml
  rules:
    - name: block-env-credential-exfil
      match: mcp.tool.name == "read_file" && mcp.tool.args.path.matches(".*(\\.env|id_rsa|credentials).*")
      action: INTERCEPT_APPROVAL
    - name: pin-package-registry
      match: mcp.tool.name == "run_command" && mcp.tool.args.command.contains("npm install")
      action: ENFORCE_EGRESS_PIN
  ```
* **Streaming Parser:** Zero-copy streaming JSON-RPC tokenizer prevents head-of-line blocking on large payload transfers.

### 5.2 Workload Identity & Locksmith Secret Injection
* **Locksmith Ephemeral Lease (ETX) Brokering:**
  * Rather than generating unvetted ad-hoc tokens or storing plaintext API keys, Aegisbox delegates credential checkout to **[Locksmith](https://github.com/bonjoski/locksmith)** (`github.com/bonjoski/locksmith/pkg/protocol`).
  * MicroVM workloads obtain short-lived, in-memory credential leases that are cryptographically bound to the guest session ID and automatically zeroed upon command or VM teardown.
* **Argus Pre-Flight AST Inspection:**
  * In-guest and host shell commands pass through **[Argus](https://github.com/bonjoski/argus)** AST inspection (`mvdan.cc/sh`) to detect reverse shells, TTY hijacking (`TIOCSTI`), and hallucinated dependency slopsquatting before execution.
* **Entropy & PRNG Seeding:**
  * To defeat the "Snapshot PRNG Clone" vulnerability, microVM pool managers explicitly force an entropy seed injection immediately upon unpausing or restoring a pooled snapshot.

---

## 6. Security Architecture & Threat Model

1. **Adversarial UI Data, Terminal Echo & Indirect Prompt Injection Defenses:**
   * All strings emitted by guest microVMs (process names, stderr logs, command-line arguments, MCP payloads) are treated as hostile text.
   * Dedicated Web Worker strips dangerous terminal control sequences: OSC 52 (clipboard hijack/injection), OSC 0/2 (window title manipulation), DCS, and cursor positioning rewrites.
   * **Terminal Query Echo Suppression:** All automated terminal emulator responses (`\x1b[c` Device Attributes, `\x1b[6n` Cursor Position Reports) are disabled to defeat PTY-echo command injection.
   * **Indirect Prompt & Visual Deception Defense:** Tool arguments in the HITL modal render exclusively as raw, monospaced plaintext without markdown evaluation (defeating fake `# APPROVED` headings). Unicode Bidi control characters (`\u202A`–`\u202E`, `\u2066`–`\u2069`) are stripped to prevent extension cloaking, and homoglyphs trigger high-contrast warning badges.

2. **Ephemeral CoW Workspace Staging, Inode Sanitization & Symlink Defenses:**
   * Host directories are mounted into the guest in read-only mode by default, backed by an in-memory or ephemeral disk upper layer (OverlayFS on Linux, APFS clonefile on macOS, VHDX differencing on Windows).
   * **Symlink Escape Defense:** All host-side commit gates and diff capture workers use `O_NOFOLLOW` and Linux `openat2` with `RESOLVE_BENEATH` (or recursive `realpath` boundary checks on macOS/Windows) to guarantee an in-guest symlink cannot point to host root directories (`/etc/shadow`, `~/.ssh`).
   * **Special Inode Rejection:** Commits strictly reject character/block device nodes (`mknod`), named pipes (FIFOs), sockets, and foreign hardlinks. Only regular files and relative symlinks can be committed.
   * Teardown automatically purges uncommitted modifications. A developer diff gate presents an interactive review of file modifications before any changes are written back to the real host working directory.

3. **Memory Isolation & Snapshot Cross-Contamination Prevention:**
   * Pre-warmed microVM snapshots are mapped using `MAP_PRIVATE` copy-on-write memory. Upon VM termination, memory regions are immediately purged via `madvise(..., MADV_DONTNEED)` and zeroed before handle release, guaranteeing zero dirty page data leakage between successive workloads.
   * Monotonic host wall-clock time (`CLOCK_MONOTONIC_RAW`) is strictly enforced for token and lease validations, preventing in-guest clock tampering from extending credentials.

4. **DNS Tunneling & Egress Containment:**
   * MicroVM network interfaces are blocked from direct outbound UDP/TCP port 53 access.
   * An embedded DNS proxy in `aegisboxd` resolves queries only for domains matching active CEL allowlists. Queries for unapproved domains are answered with `NXDOMAIN` without performing upstream lookups, stopping async DNS tunneling exfiltration in its tracks.

5. **Local IPC Boundary Hardening & PID-Reuse Elimination:**
   * **Linux:** Communication socket (`~/.aegisbox/aegisboxd.sock`) enforces POSIX file mode `0600`, parent directory permissions check (`0700`, non-symlink), and `SO_PEERCRED` validation.
   * **macOS:** Enforces `LOCAL_PEERCRED` UID check (`cr_uid == getuid()`) and `LOCAL_PEERTOKEN` audit validation, eliminating rapid PID rollover race conditions.
   * **Windows:** Named Pipe (`\\.\pipe\aegisboxd`) enforces a strict DACL locked exclusively to the current user SID (`SDDL: D:(A;;GRGW;;;<UserSID>)`), verified via `ImpersonateNamedPipeClient()` and verified token SID extraction.
   * Ephemeral 256-bit cryptographically random session tokens are negotiated during handshake.

6. **Human-in-the-Loop Anti-Clickjacking & Biometric Step-Up:**
   * **Dwell Timer:** 800ms mandatory click delay on the "Approve" button upon modal popup, preventing automated background focus-stealing and keystroke spamming.
   * **Event Integrity:** Asserting `event.isTrusted === true` to defeat programmatic DOM click synthesizers.
   * **Locksmith Biometric Escalation:** Mandatory Touch ID (macOS), Windows Hello (Windows), or PAM/Polkit (Linux) confirmation via Locksmith native protocol for any action tagged `CRITICAL` severity.

7. **L7 Parser Differential & Smuggling Defenses:**
   * Rejects JSON payloads with duplicate object keys.
   * Validates UTF-8 encoding, canonicalizes path targets, and re-serializes parsed AST objects before forwarding to downstream MCP tool servers, eliminating parser differential smuggling.

8. **Enterprise Precedence Hierarchy & TOCTOU-Free Upgrades:**
   * Strict non-overridable policy resolution: Tier 1 (Machine MDM / GPO / `/etc`) > Tier 2 (Repo Workspace `.aegisbox/policy.yaml`) > Tier 3 (User `~/.aegisbox/config.yaml`). Lower tiers can only tighten security, never loosen it.
   * Tauri auto-updater downloads to restricted staging directories (`0700`), verifies Ed25519 signatures in memory, and performs atomic replacement (`renameat2` / `MoveFileEx`) to prevent TOCTOU tampering.
   * Session audit logs are cryptographically hash-chained (Merkle/sequence chained) and Ed25519-signed via OS secure hardware keystores (Secure Enclave, TPM 2.0).

---

## 7. Phased Implementation Roadmap (Tri-Platform 20-Week Execution Plan)

```
Sprint 1 (Wks 1-4)   ├── [COMPLETED] Daemon, Network Helper & Tri-Platform IPC Foundation ──► [phase-1-daemon-ipc.md](phase-1-daemon-ipc.md)
Sprint 2 (Wks 5-8)   ├── Multi-Transport MCP Firewall & Locksmith Secret Broker ─► [phase-2-mcp-cow-identity.md](phase-2-mcp-cow-identity.md)
Sprint 3 (Wks 9-12)  ├── Tauri Desktop Cockpit (Fabrial Integration) & CLI Parity ──► [phase-3-tauri-desktop.md](phase-3-tauri-desktop.md)
Sprint 4 (Wks 13-16) ├── High-Throughput Observability Console & Audit Pipeline ──► [phase-4-observability-audit.md](phase-4-observability-audit.md)
Sprint 5 (Wks 17-20) ├── Multi-Platform Fuzzing, Model-Runner Range & Release ───► [phase-5-hardening-release.md](phase-5-hardening-release.md)
```

### [Phase 1: Daemon, Privileged Network Helper & IPC Foundation (Weeks 1–4) — ✅ COMPLETED & VERIFIED](phase-1-daemon-ipc.md)
*Detailed technical breakdown, Protobuf schemas, and sprint schedule available in [phase-1-daemon-ipc.md](phase-1-daemon-ipc.md).*
* **Deliverables:**
  * Formalize Protobuf / gRPC schema for daemon IPC.
  * Implement headless `aegisboxd` daemon in Go/Rust with POSIX Unix socket and Windows Named Pipe support.
  * Build decoupled privileged helper (`aegisbox-netd`): `systemd` on Linux, `launchd` on macOS, and Windows Service with **Windows Filtering Platform (WFP)** driver/API bindings.
  * Implement hypervisor lifecycle handlers: Linux KVM, Apple `Virtualization.framework`, and Windows Host Compute System (`hcsshim`).
* **Exit Criteria & Verification:**
  * CLI successfully creates, boots, and terminates microVMs over the local IPC channel in `<30ms` (Linux) and `<80ms` (macOS & Windows) without persistent root execution.

### [Phase 2: Multi-Transport MCP Firewall, Locksmith Secrets & CoW Storage (Weeks 5–8) — ✅ COMPLETED & VERIFIED](phase-2-mcp-cow-identity.md)
*Detailed technical breakdown, CEL policy schemas, and storage specs available in [phase-2-mcp-cow-identity.md](phase-2-mcp-cow-identity.md).*
* **Deliverables:**
  * Build stdio, vsock / `AF_HYPERV`, and HTTP/SSE Layer-7 MCP proxy with CEL rule engine.
  * Implement CoW workspace staging: OverlayFS (Linux), APFS clonefile (macOS), and VHDX differencing (Windows) with special inode rejection.
  * **Locksmith Integration:** Wire `github.com/bonjoski/locksmith/pkg/protocol` for ephemeral ETX secret leases into microVM memory.
  * **Argus & SBOM-Enricher:** Integrate Argus AST decomposition (`mvdan.cc/sh`), slopsquatting detection, and SBOM-Enricher license/checksum validation.
* **Exit Criteria & Verification:**
  * AI agent MCP tool calls are intercepted in real time. Ephemeral writes leave host files 100% unmodified across all 3 OSes until explicitly committed.

### [Phase 3: Tauri Desktop Cockpit (Fabrial Integration) & CLI Parity (Weeks 9–12) — ✅ COMPLETED & VERIFIED](phase-3-tauri-desktop.md)
*Detailed technical breakdown, HITL state machine, and Svelte 5 specs available in [phase-3-tauri-desktop.md](phase-3-tauri-desktop.md).*
* **Deliverables:**
  * Scaffold Tauri v2 Rust bridge with strict command scopes for macOS (WebKit), Linux (WebKitGTK), and Windows (WebView2).
  * **Fabrial Multi-Tier Tray:** Implement tray switcher toggling between Permissive, Airlock Tier 1 (kernel sandbox), and Aegisbox Tier 2 (microVM).
  * Build interactive HITL approval sheet with Locksmith biometric gating (Touch ID / Windows Hello) for `CRITICAL` severity actions.
  * Implement full headless CLI fallback (`aegisbox approve`) for SSH, WSL2, and Windows Terminal.
* **Exit Criteria & Verification:**
  * Desktop tray functions seamlessly across macOS, Linux, and Windows. Approval sheets intercept tool execution reliably with zero UI blocking.

### [Phase 4: High-Throughput Observability Console & Audit Pipeline (Weeks 13–16) — ✅ COMPLETED & VERIFIED](phase-4-observability-audit.md)
*Detailed technical breakdown, OffscreenCanvas worker, and DAG visualizer available in [phase-4-observability-audit.md](phase-4-observability-audit.md).*
* **Deliverables:**
  * Implement Svelte 5 streaming telemetry console with OffscreenCanvas ring buffer.
  * Build live egress network connection map and canary tripwire alert visualizer.
  * Add cryptographically signed session audit log export with hash-chain non-repudiation (Ed25519 signed JSONL).
* **Exit Criteria & Verification:**
  * UI renders continuous 10,000 lines/sec streaming logs and tool-call graphs while maintaining `<60MB` RSS on macOS WKWebView, `<70MB` on Windows WebView2, and `<35MB` on Linux.

### [Phase 5: Multi-Platform Hardening, Model-Runner Range & Release (Weeks 17–20) — ✅ COMPLETED & VERIFIED](phase-5-hardening-release.md)
*Detailed technical breakdown, fuzzing harnesses, MDM/GPO templates, and packaging scripts available in [phase-5-hardening-release.md](phase-5-hardening-release.md).*
* **Deliverables:**
  * Conduct IPC fuzzing, device model audit, and adversarial bypass verification across KVM, VZ, and HCS.
  * Implement enterprise fleet configuration locks: macOS `.plist`, Linux `/etc/aegisbox/policy.json`, and Windows Registry GPO (`HKLM\Software\Policies\Aegisbox`).
  * **Model-Runner Benchmark Evaluation:** Execute automated multi-agent test suite using `github.com/bonjoski/model-runner` running real agents (`agi`/`agy`, Claude Code, Cursor) against 50 weaponized escape scenarios.
  * Package installers: macOS Universal `.dmg` / `.pkg`, Linux `.deb` / `.rpm` / `.AppImage`, and Windows signed `.msi` / `.exe` bundle with WebView2 bootstrapper.
* **Exit Criteria & Verification:**
  * Zero high/critical findings from fuzzing suite. End-to-end multi-agent evaluation matrices pass with zero host escapes on all three platforms.

---

## 8. Adversarial Quality & Security Gatekeeping Protocol (Phase Gates)

Rather than performing further speculative document reviews, engineering quality and security are enforced through a strict **Dual-Gate Adversarial Sentinel Protocol** applied at the **beginning and end of each implementation phase**:

```
                       ┌────────────────────────────────────────────────────────┐
                       │               PHASE INCEPTION (ENTRY GATE)             │
                       │  • Freeze interface contracts (Protobuf / CEL schemas) │
                       │  • Author negative / red-team test cases upfront       │
                       │  • Review known evasion vectors for that phase         │
                       └──────────────────────────┬─────────────────────────────┘
                                                  │
                                                  ▼
                       ┌────────────────────────────────────────────────────────┐
                       │               ACTIVE SPRINT EXECUTION                  │
                       │  • Feature implementation (Go / Rust / Svelte 5)       │
                       │  • Continuous unit tests & bench latency profiling     │
                       └──────────────────────────┬─────────────────────────────┘
                                                  │
                                                  ▼
                       ┌────────────────────────────────────────────────────────┐
                       │               PHASE COMPLETION (EXIT GATE)             │
                       │  • Automated scanner pass (sentinel_audit.py)          │
                       │  • Fuzzing harness run & adversarial delta audit       │
                       │  • Formal signoff against phase Exit Criteria          │
                       │  • ZERO-BYPASS POLICY: High/Crit findings block merge  │
                       └────────────────────────────────────────────────────────┘
```

### Entry Gate Protocol (Start of Each Phase)
1. **Contract Freeze:** Review and lock all public APIs, Protobuf messages, or Tauri IPC channels for that phase before writing implementation code.
2. **Adversarial Test-Driven Development (TDD):** Author weaponized / negative test cases *first* (e.g. malformed inputs, symlink traps, timing attacks, DNS tunnel patterns). Feature code is only complete when these attack vectors are actively trapped and reported.

### Exit Gate Protocol (End of Each Phase)
1. **Automated Sentinel Scan:** Execute the automated code audit scanner:
   ```bash
   python3 /Users/benskolmoski/.super.engineering/hooks/antigravity-customization/.agents/skills/adversarial-sentinel/scripts/sentinel_audit.py --path .
   ```
2. **Delta Code Review:** Perform a manual peer review specifically searching for:
   - Go non-wrapped errors (`fmt.Errorf` without `%w`) and ignored errors (`_ = ...`).
   - Rust direct `.unwrap()` in production or error-propagation paths.
   - Unsanitized string interpolations in system commands or firewall rules.
   - TOCTOU filesystem races.
3. **Zero-Bypass Merge Rule:** No phase is considered complete, and no branch is merged to `main`, if any high or critical vulnerability remains unmitigated.

---

## 9. Engineering Specifications & Key Metrics

| Metric | Target Specification | Verification Method |
| :--- | :--- | :--- |
| **Linux MicroVM Boot Latency** | `<30 milliseconds` (cold start via snapshot pool) | IPC `StartVM` to guest userspace init via vsock heartbeat. |
| **macOS MicroVM Boot Latency** | `<80 milliseconds` | Apple `VZVirtualMachine` pooled instance unpause. |
| **Windows MicroVM Boot Latency** | `<80 milliseconds` | Windows HCS utility VM resume. |
| **Client Memory Ceiling (Linux)** | `<35MB` idle RSS / `<60MB` active streaming | Resident set size monitored across WebKitGTK processes. |
| **Client Memory Ceiling (macOS)**| `<60MB` idle RSS / `<85MB` active streaming | Resident set size monitored across `WKWebView` processes. |
| **Client Memory Ceiling (Windows)**| `<50MB–70MB` idle RSS / `<90MB` active streaming | Resident set size monitored across `WebView2` runtime processes. |
| **Local IPC Round-Trip** | `<2 milliseconds` | End-to-end benchmark between Tauri Rust bridge and `aegisboxd` (Unix socket / Named Pipe). |
| **Zero Host Contamination** | `100%` clean host state on guest cancellation | Automated test verifying SHA256 integrity of host workspace after malicious guest execution (`rm`, encrypt, overwrite). |
| **Audit Log Integrity** | `100%` Ed25519 signed session logs | Cosign / Sigstore validation against exported trace artifacts. |

---

## 10. Directory & Implementation Mapping

Rather than performing further speculative document reviews, engineering quality and security are enforced through a strict **Dual-Gate Adversarial Sentinel Protocol** applied at the **beginning and end of each implementation phase**:

```
                       ┌────────────────────────────────────────────────────────┐
                       │               PHASE INCEPTION (ENTRY GATE)             │
                       │  • Freeze interface contracts (Protobuf / CEL schemas) │
                       │  • Author negative / red-team test cases upfront       │
                       │  • Review known evasion vectors for that phase         │
                       └──────────────────────────┬─────────────────────────────┘
                                                  │
                                                  ▼
                       ┌────────────────────────────────────────────────────────┐
                       │               ACTIVE SPRINT EXECUTION                  │
                       │  • Feature implementation (Go / Rust / Svelte 5)       │
                       │  • Continuous unit tests & bench latency profiling     │
                       └──────────────────────────┬─────────────────────────────┘
                                                  │
                                                  ▼
                       ┌────────────────────────────────────────────────────────┐
                       │               PHASE COMPLETION (EXIT GATE)             │
                       │  • Automated scanner pass (sentinel_audit.py)          │
                       │  • Fuzzing harness run & adversarial delta audit       │
                       │  • Formal signoff against phase Exit Criteria          │
                       │  • ZERO-BYPASS POLICY: High/Crit findings block merge  │
                       └────────────────────────────────────────────────────────┘
```

### Entry Gate Protocol (Start of Each Phase)
1. **Contract Freeze:** Review and lock all public APIs, Protobuf messages, or Tauri IPC channels for that phase before writing implementation code.
2. **Adversarial Test-Driven Development (TDD):** Author weaponized / negative test cases *first* (e.g. malformed inputs, symlink traps, timing attacks, DNS tunnel patterns). Feature code is only complete when these attack vectors are actively trapped and reported.

### Exit Gate Protocol (End of Each Phase)
1. **Automated Sentinel Scan:** Execute the automated code audit scanner:
   ```bash
   python3 /Users/benskolmoski/.super.engineering/hooks/antigravity-customization/.agents/skills/adversarial-sentinel/scripts/sentinel_audit.py --path .
   ```
2. **Delta Code Review:** Perform a manual peer review specifically searching for:
   - Go non-wrapped errors (`fmt.Errorf` without `%w`) and ignored errors (`_ = ...`).
   - Rust direct `.unwrap()` in production or error-propagation paths.
   - Unsanitized string interpolations in system commands or firewall rules.
   - TOCTOU filesystem races.
3. **Zero-Bypass Merge Rule:** No phase is considered complete, and no branch is merged to `main`, if any high or critical vulnerability remains unmitigated.

---

## 8. Engineering Specifications & Key Metrics

| Metric | Target Specification | Verification Method |
| :--- | :--- | :--- |
| **Linux MicroVM Boot Latency** | `<30 milliseconds` (cold start via snapshot pool) | IPC `StartVM` to guest userspace init via vsock heartbeat. |
| **macOS MicroVM Boot Latency** | `<80 milliseconds` | Apple `VZVirtualMachine` pooled instance unpause. |
| **Windows MicroVM Boot Latency** | `<80 milliseconds` | Windows HCS utility VM resume. |
| **Client Memory Ceiling (Linux)** | `<35MB` idle RSS / `<60MB` active streaming | Resident set size monitored across WebKitGTK processes. |
| **Client Memory Ceiling (macOS)**| `<60MB` idle RSS / `<85MB` active streaming | Resident set size monitored across `WKWebView` processes. |
| **Client Memory Ceiling (Windows)**| `<50MB–70MB` idle RSS / `<90MB` active streaming | Resident set size monitored across `WebView2` runtime processes. |
| **Local IPC Round-Trip** | `<2 milliseconds` | End-to-end benchmark between Tauri Rust bridge and `aegisboxd` (Unix socket / Named Pipe). |
| **Zero Host Contamination** | `100%` clean host state on guest cancellation | Automated test verifying SHA256 integrity of host workspace after malicious guest execution (`rm`, encrypt, overwrite). |
| **Audit Log Integrity** | `100%` Ed25519 signed session logs | Cosign / Sigstore validation against exported trace artifacts. |

---

## 9. Directory & Implementation Mapping

The roadmap deliverables map directly into the existing Aegisbox codebase structure:

```
aegisbox/
├── cmd/
│   ├── aegisbox/          # Unified CLI entrypoint (with headless approve commands)
│   ├── aegisboxd/         # Tier 2 Daemon headless orchestration engine
│   ├── aegisbox-netd/     # Tier 2b Minimal privileged network helper (Linux / macOS / Windows)
│   └── aegisbox-guest/    # In-guest microVM lightweight init & vsock / HCS agent
├── desktop/               # Tier 1 Tauri v2 Desktop Application
│   ├── src-tauri/         # Rust bridge, system tray, and local IPC client
│   └── src/               # Svelte 5 + TailwindCSS + OffscreenCanvas UI
├── pkg/
│   ├── argus/             # Shell AST decomposition & slopsquatting detection
│   ├── mcp/               # L7 MCP protocol proxy (stdio, vsock, SSE) & CEL engine
│   ├── netgate/           # Ephemeral network anchors (pfctl, nftables, WFP tripwires)
│   ├── vmm/               # Hypervisor abstraction (Apple VZ, Firecracker KVM, Windows HCS)
│   └── workspace/         # CoW OverlayFS, APFS clonefile, and ReFS/VHDX differencing staging
└── docs/
    └── roadmap/           # Unified platform specifications and phase tracking
```
