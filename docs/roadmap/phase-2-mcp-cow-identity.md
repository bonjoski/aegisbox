# Phase 2: Multi-Transport MCP Firewall, CoW Storage & Workload Identity
## Technical Execution Specification & Engineering Work-Breakdown (Weeks 5–8)

**Status:** Completed & Verified (Exit Gate Passed)  
**Owner:** Security & Storage Engineering  
**Dependencies:** Phase 1 (Daemon, IPC & MicroVM Lifecycle)  
**Target Repositories/Packages:** `pkg/mcp`, `pkg/workspace`, `pkg/identity`, `pkg/argus`

---

## 1. Overview & Objective

Phase 2 builds the semantic inspection firewall and data containment layers of Aegisbox. It introduces real-time Layer-7 mediation of Model Context Protocol (MCP) tool executions, cryptographic zero-contamination storage using Copy-on-Write (CoW) overlays, and local SPIFFE measured identity brokering inside isolated microVMs.

**Exit Criterion:** AI coding agents communicating via stdio, vsock, or HTTP/SSE have their tool calls intercepted and evaluated against CEL policies. Ephemeral workspace modifications remain 100% contained in an ephemeral upper layer with zero host disk contamination prior to review.

---

## 2. Architecture & File Layout

```
aegisbox/
├── pkg/
│   ├── mcp/
│   │   ├── proxy.go                 # Bidirectional JSON-RPC streaming proxy
│   │   ├── transport_stdio.go       # stdio multiplexer for agent-to-server pipes
│   │   ├── transport_vsock.go       # vsock socket bridge to guest MCP servers
│   │   ├── transport_sse.go         # HTTP Server-Sent Events reverse proxy
│   │   ├── policy_cel.go            # Common Expression Language (CEL) policy engine
│   │   └── schema.go                # JSON-RPC 2.0 message schemas & AST models
│   ├── workspace/
│   │   ├── cow_linux.go             # OverlayFS ephemeral upper-dir mount
│   │   ├── cow_darwin.go            # APFS clonefile staging directory tree
│   │   ├── cow_windows.go           # ReFS block clone / VHDX differencing disk
│   │   ├── diff_capture.go          # Git worktree diff generator & stat tracker
│   │   └── commit_gate.go           # Cryptographic hash verifier & review gate
│   ├── identity/
│   │   ├── spiffe_broker.go         # Local loopback SVID broker
│   │   ├── attestation.go           # MicroVM measurement verifier (hash/cmdline)
│   │   └── entropy.go               # virtio-rng dynamic re-seeding engine
│   └── argus/
│       ├── lockfile_validator.go    # SHA256 integrity verifier (package-lock, Cargo.lock)
│       └── slopsquat_filter.go      # Pre-flight package hallucination detector
```

---

## 3. CEL Policy Schema Specification

Policies are authored in declarative Common Expression Language (CEL) rules that evaluate incoming MCP JSON-RPC requests before they reach the tool execution layer:

```yaml
version: "v1"
rules:
  # Rule 1: Intercept sensitive credential access
  - id: "rule-credential-shield"
    description: "Intercept any file reading targeting sensitive keys or configs"
    match: >
      mcp.tool == "read_file" && (
        mcp.args.path.matches(".*(\\.env|id_rsa|\\.aws|credentials).*") ||
        mcp.args.path.startsWith("/etc/")
      )
    action: "INTERCEPT_APPROVAL"
    severity: "HIGH"

  # Rule 2: Enforce pinned package registries
  - id: "rule-lockfile-tamper-guard"
    description: "Block unvetted external package registry egress"
    match: >
      mcp.tool == "run_command" && (
        mcp.args.command.matches(".*(npm|pip|cargo|go)\\s+(install|add|get).*") &&
        !mcp.args.command.contains("--registry")
      )
    action: "ENFORCE_EGRESS_PIN"
    severity: "MEDIUM"

  # Rule 3: Block destructive filesystem commands
  - id: "rule-prevent-root-destructive"
    description: "Block dangerous wildcards and raw disk write commands"
    match: >
      mcp.tool == "run_command" && 
      mcp.args.command.matches(".*(rm\\s+-rf\\s+[/~]|dd\\s+if=).*")
    action: "DENY"
    severity: "CRITICAL"
```

---

## 4. Week-by-Week Implementation Plan

### Week 5: Multi-Transport MCP JSON-RPC Proxy Engine
* **Tasks:**
  1. Implement `pkg/mcp/proxy.go` providing a zero-copy streaming JSON-RPC 2.0 parser.
  2. **Adversarial JSON Smuggling & Parser Differential Defenses:**
     - Reject payloads with duplicate object keys (prevents parser differential bypasses where firewall sees key A but server parses key B).
     - Canonicalize and validate UTF-8 encoding; reject unescaped control characters and invalid homoglyphs in file paths.
     - **Re-serialization Pipeline:** After CEL policy evaluation passes, re-serialize the parsed AST rather than forwarding raw bytes downstream, ensuring downstream servers receive strictly normalized JSON.
  3. Implement `transport_stdio.go`: Wrap stdin/stdout of child processes, intercepting `tools/call`, `resources/read`, and `prompts/get`.
  4. Implement `transport_vsock.go`: Connect host proxy to guest microVM over vsock port `50051`.
  5. Implement `transport_sse.go`: Act as an HTTP reverse proxy for SSE-based MCP servers.
* **Testing:** Run mock MCP tool call sequences; verify that message ordering is strictly preserved and latency overhead remains `<1.5ms`. Fuzz with duplicate keys, UTF-8 overlong encodings, and malformed JSON-RPC frames.

### Week 6: Common Expression Language (CEL) Engine, DNS Proxy & Intercept Gate
* **Tasks:**
  1. Integrate `github.com/google/cel-go` into `pkg/mcp/policy_cel.go`.
  2. **Adversarial DNS Tunneling & Egress Exfiltration Defense:**
     - Block all direct outbound UDP/TCP port 53 traffic from the microVM TAP interface.
     - Provide an embedded, local DNS proxy in `aegisboxd` bound strictly to the microVM gateway IP.
     - Evaluate all domain queries against the CEL allowlist *prior* to resolving. Queries for unapproved domains (e.g. `<secret>.attacker.com`) are immediately replied to with `NXDOMAIN` without performing any upstream network lookup, defeating DNS-based data exfiltration.
  3. Map incoming MCP messages to strongly typed CEL activation environments:
     - `mcp.tool` (string)
     - `mcp.args` (map[string]any)
     - `session.workspace` (string)
     - `session.profile` (string)
  4. Build intercept event channel: When a rule matches `INTERCEPT_APPROVAL`, suspend JSON-RPC response, emit an intercept event to `aegisboxd`, and await authorization.
* **Testing:** Execute 1,000 synthetic tool calls against positive and negative test cases. Test DNS tunneling exploit attempting to exfiltrate base64 secrets in subdomains; verify all queries are blocked with `NXDOMAIN` and zero upstream packets leave host.

### Week 7: Zero-Host-Contamination Ephemeral CoW Storage & Inode Sanitization
* **Tasks:**
  1. Implement `pkg/workspace/cow_linux.go`:
     - Mount host workspace as read-only lower dir with `nodev`, `nosuid` flags.
     - Create ephemeral tmpfs upper and work dirs.
     - Mount merged OverlayFS into microVM via Virtio-FS.
  2. Implement `pkg/workspace/cow_darwin.go`:
     - Create shadow staging directory using `clonefile()` (APFS fast CoW copy).
     - Bind shadow directory to Apple `VZVirtioFileSystemDeviceConfiguration`.
  3. Implement `pkg/workspace/cow_windows.go`:
     - Create differencing VHDX or ReFS cloned tree mounted into HCS utility VM.
  4. Implement `diff_capture.go` & `commit_gate.go`:
     - **Symlink & Special File (Inode) Defense:**
       - All diff inspection and commit operations on the host MUST use `O_NOFOLLOW` and Linux `openat2` with `RESOLVE_BENEATH`.
       - On macOS and Windows, recursively resolve canonical paths using `realpath` and reject any file entry pointing outside the workspace root.
       - **Special File Rejection:** Explicitly reject and abort commits if the upper layer contains device nodes (`mknod`), FIFOs/named pipes, Unix domain sockets, or hardlinks pointing to inodes outside the ephemeral tree. Only regular files and vetted relative symlinks are allowed.
     - Compute clean Git status diff between lower and upper layers.
     - Provide atomic commit gate: Only user-approved file diffs are synced back to host working directory.
* **Testing:** Execute an adversarial guest script (`mknod bad_node c 1 3 && mkfifo bad_fifo && ln -s /etc/shadow leaked_shadow`). Terminate VM. Verify host directory remains 100% byte-for-byte identical, and diff gate flags and rejects all special inodes.

### Week 8: Locksmith Secret Brokering, Argus Pre-Flight & Bomhound
* **Tasks:**
  1. **Locksmith Ephemeral Lease (ETX) Integration:**
     - Integrate `github.com/bonjoski/locksmith/pkg/protocol` and `pkg/locksmith`.
     - In-guest microVM requests credentials over vsock; host daemon checks out short-lived, ephemeral leases directly from the local Locksmith biometric vault.
     - Enforce zero ambient plaintext credentials: keys are held strictly in guest memory and cryptographically scrubbed upon exit.
  2. Implement `pkg/identity/entropy.go`:
     - Push 256 bytes of cryptographically secure random bytes via `virtio-rng` immediately upon VM resume.
  3. **Argus AST Pre-Flight & Slopsquatting Gate:**
     - Connect `github.com/bonjoski/argus` AST parser (`mvdan.cc/sh`) to analyze all shell tool executions before microVM dispatch.
     - Block hallucinated package slopsquats against live PyPI, npm, and crates.io registries.
  4. **Bomhound Dependency & License Audit:**
     - Integrate `github.com/bonjoski/bomhound` verification logic to audit CycloneDX SBOMs and lockfile checksums against upstream sources, flagging untrusted licenses or mismatched digests.
* **Testing:** End-to-end test executing agent tool requiring API key; verify key is fetched dynamically via Locksmith biometric lease and scrubbed upon VM shutdown. Test npm install with poisoned package name; verify Argus trips and halts execution in <1ms.

---

## 5. Verification Matrix & Exit Criteria

| Test Case | Target / Threshold | Command / Verification |
| :--- | :--- | :--- |
| **MCP Proxy Overhead** | `<1.5ms` added latency per tool call | `go test -bench=BenchmarkMCPProxyLatency ./pkg/mcp` |
| **CEL Rule Evaluation** | `<200 microseconds` per rule set | `go test -bench=BenchmarkCELEvaluation ./pkg/mcp` |
| **Zero Host Contamination** | 0 bytes leaked / 100% host integrity | `go test -run=TestZeroContamination_OverlayFS ./pkg/workspace` |
| **APFS Clonefile Speed** | `<50ms` shadow workspace creation | `go test -run=TestAPFSClonefileSpeed ./pkg/workspace` |
| **Lockfile Tamper Detection** | 100% detection rate of modified hashes | `go test -run=TestLockfileTamper ./pkg/argus` |
