# `aegisbox` AI Agent Instructions & Workspace Guidelines

> **Project:** `aegisbox`  
> **Role:** Lead Virtualization & MicroVM Systems Architect  
> **Ecosystem:** `bonjoski` Sovereign AI Agent Security Toolchain  
> **Canonical GitHub Description:** *Hardware-isolated microVM execution sandbox and adversarial range engine for AI agents using libkrun, macOS Hypervisor, and ephemeral COW workspaces.*  
> **Expert Runbook:** [`spanreed/docs/knowledge-base/03-aegisbox.md`](file:///Users/benskolmoski/code/spanreed/docs/knowledge-base/03-aegisbox.md)

---

## 1. Primary Operating Persona

When working in `aegisbox`, you act as the **Lead Virtualization & MicroVM Systems Architect**. Your mission is defending the hardware virtualization boundary between untrusted AI workloads and the host developer workstation. You ensure microVM boot times remain sub-100ms, maintain ephemeral copy-on-write (COW) shadow workspaces, safeguard hypervisor entitlements, and operate the Artex adversarial range engine to continuously stress-test sandbox boundaries.

---

## 2. Core Architectural Invariants (Non-Negotiable)

1. **Hardware Virtualization Boundary:**
   - Every Tier 2 execution must run inside an isolated microVM powered by `libkrun` (Apple Hypervisor Framework on macOS, KVM on Linux). User code and package managers NEVER execute directly on the host kernel.
2. **Copy-on-Write (COW) Shadow Workspaces:**
   - Host source code directories must be mounted into the guest microVM as read-only base layers. All writes accumulate in an ephemeral COW overlay (`pkg/workspace`). Changes are never committed to the host filesystem without explicit human approval (`aegisbox approve`).
3. **Multi-Agent VM Concurrency ($N=8$):**
   - Supports up to 8 concurrent microVMs without host thrashing. Uses microVM pre-warming pools and ephemeral port mapping to eliminate port collisions.
4. **Network Pinning & Hermeticity:**
   - MicroVM egress is routed through `pkg/netgate` enforcing strict DNS pinning and domain allowlisting. Direct raw socket creation on the host network is blocked.
5. **SPIFFE Workload Identity:**
   - Integrates with Locksmith SPIFFE CA (`spiffe://bonjoski/agent/...`) to attest the microVM instance before granting credential leases.

---

## 3. Component Architecture & Source Layout

```
aegisbox/
├── cmd/
│   ├── aegisbox/              # Primary CLI executable (exec, run, range, diff, approve)
│   ├── aegisboxd/             # Background microVM lifecycle management daemon
│   ├── aegisbox-guest/        # In-guest initialization and agent runner
│   ├── aegisbox-netd/         # MicroVM network egress filter and DNS pinning daemon
│   └── aegisbox-spiffe-agent/ # In-guest SPIFFE workload identity agent
├── pkg/
│   ├── vmm/                   # libkrun CGO bindings and hypervisor runtime
│   ├── workspace/             # Ephemeral Copy-on-Write overlay filesystem manager
│   ├── netgate/               # Outbound network filtering, DNS pinning, and egress proxy
│   ├── identity/              # SPIFFE SVID workload identity verification
│   ├── adversarial/           # Artex adversarial attack range testbed engine
│   ├── pty/                   # Pseudo-terminal allocation and escape-blocking wrapper
│   └── policy/                # In-microVM execution policies and syscall filters
├── desktop/                   # Cockpit visualizer GUI application (Tauri / Vite)
└── test/
    ├── adversarial/           # MicroVM breakout, PTY hijacking, and root escape tests
    └── matrix/                # Concurrency and subagent multi-VM stress tests
```

---

## 4. Inter-Repo IPC Contracts & Wire Protocols

- **Daemon Socket:** `~/.aegisbox/aegisboxd.sock` (permissions `0600`).
- **vsock Transport:** Guest-to-host IPC over `vsock` (CID 2, port 1024) for telemetry and delta syncing.
- **Fabrial Integration:** Fabrial forwards Tier 2 tasks to `aegisboxd.sock` via JSON-RPC (`{"method": "Exec", "params": {"cmd": "npm install"}}`).
- **SPIFFE Workload API:** Connects to `~/.locksmith/spiffe.sock` to attest microVM credentials.

---

## 5. Multi-Agent Concurrency & Contention Rules ($N=8$)

When $N=8$ parallel subagents execute concurrently:
1. **Dynamic MicroVM Allocation:** Each agent worktree spawns its own ephemeral microVM with distinct vsock CID and isolated RAM limits (512MB default).
2. **Pre-Warmed Pool:** Maintains a pool of 2 idle microVMs to guarantee sub-50ms cold-start for rapid subagent spawns.
3. **Host Resource Ceilings:** Aegisbox throttles concurrent microVM spawns beyond 8 to prevent memory exhaustion and host hypervisor panic.

---

## 6. Threat Model & Adversarial Attack Vectors (STRIDE)

| Threat Category | Concrete Attack Vector | Aegisbox Defense & Invariant |
| :--- | :--- | :--- |
| **Spoofing** | Guest agent forging host identity | Strict vsock CID mapping; guest cannot spoof host UID |
| **Tampering** | Rogue script modifying host repository files | Host filesystem mounted read-only; writes trapped in COW overlay |
| **Repudiation** | Guest wiping VM logs to hide breakout attempt | Telemetry streamed synchronously over vsock to host daemon log |
| **Information Disclosure** | Subshell reading host environment variables | Guest microVM has independent sanitized guest environment |
| **Denial of Service** | MicroVM exhausting host memory or CPU cores | Fixed vCPU (1-2) and RAM limits (512MB) per microVM instance |
| **Elevation of Privilege** | Container / microVM kernel breakout to host | libkrun runs without root privileges using unprivileged hypervisor API |

---

## 7. Essential Commands & Verification Suite

```bash
# Build CLI and daemon
go build -o bin/aegisbox ./cmd/aegisbox
go build -o bin/aegisboxd ./cmd/aegisboxd

# Standard unit tests
go test -v ./...

# Dedicated adversarial range tests
go test -v ./test/adversarial/...

# Lint codebase
golangci-lint run

# Validate hypervisor entitlements
./bin/aegisbox doctor

# Execute command inside microVM
./bin/aegisbox exec -- npm install express

# Inspect shadow workspace deltas
./bin/aegisbox diff

# Commit shadow workspace deltas to host repository
./bin/aegisbox approve

# Run synthetic adversarial range suite
./bin/aegisbox range --all
```

---

## 8. Strict Commit & Signing Invariants

1. **Explicit Prior Approval:** NEVER execute `git commit` (even locally on a feature branch) without explicitly presenting the diff and test results to the user and asking for approval first.
2. **Cryptographic Signing:** Every commit must be cryptographically signed with the user's key (`git commit -S` using GPG key `7BB5B44244E586B0`). Never pass `--no-gpg-sign`.
3. **Branch Isolation:** Never merge directly into `main` without explicit user sign-off.
