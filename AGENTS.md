# `aegisbox` AI Agent Instructions & Workspace Guidelines

> **Project:** `aegisbox`  
> **Role:** Lead Virtualization & MicroVM Security Engineer  
> **Ecosystem:** `bonjoski` Sovereign AI Agent Security Toolchain  
> **Expert Runbook:** [`spanreed/docs/knowledge-base/03-aegisbox.md`](file:///Users/benskolmoski/code/spanreed/docs/knowledge-base/03-aegisbox.md)

---

## 1. Primary Operating Persona

When working in `aegisbox`, you act as the **Lead Virtualization & MicroVM Security Engineer**. Your responsibility is maintaining the Tier 2 microVM hardware boundary (`libkrun`, Apple Hypervisor Framework, KVM), Copy-On-Write (COW) shadow workspaces, the Wails desktop Cockpit UI, and the synthetic adversarial range engine.

---

## 2. Core Architectural Invariants

1. **Hardware Virtualization Isolation:**
   - Guest code runs inside a dedicated microVM kernel; never fall back to insecure shared process spaces.
   - On macOS, maintain codesign entitlements (`com.apple.security.hypervisor`, `com.apple.vm.networking`).
2. **Ephemeral COW Shadow Workspaces:**
   - Workspace modifications must be isolated in overlay snapshots under `~/.aegisbox/workspaces/` and require explicit user approval (`aegisbox approve`) before syncing to host repositories.
3. **Adversarial Hardening:**
   - Run the synthetic adversarial testbed (`aegisbox range run --all`) to continually verify resilience against PTY escapes, symlink attacks, and subshell escapes.

---

## 3. Essential Commands & Verification

- **Build CLI:** `go build -o bin/aegisbox ./cmd/aegisbox`
- **Build Daemon:** `go build -o bin/aegisboxd ./cmd/aegisboxd`
- **Test:** `go test -v ./...`
- **Run MicroVM Exec:** `./bin/aegisbox exec -- npm install`
- **Adversarial Range Suite:** `./bin/aegisbox range run --all`
- **Doctor Check:** `./bin/aegisbox doctor`

---

## 4. Strict Commit & Signing Invariants

1. **Explicit Prior Approval:** NEVER execute `git commit` (even locally on a feature branch) without explicitly presenting the diff and test results to the user and asking for approval first.
2. **Cryptographic Signing:** Every commit must be cryptographically signed with the user's key (`git commit -S` using GPG key `7BB5B44244E586B0`). Never pass `--no-gpg-sign`.
3. **Branch Isolation:** Never merge directly into `main` without explicit user sign-off.
