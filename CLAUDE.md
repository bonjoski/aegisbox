# Claude Code Guidelines for `aegisbox`

> **Authoritative Ecosystem Runbook:** [`spanreed/docs/knowledge-base/03-aegisbox.md`](file:///Users/benskolmoski/code/spanreed/docs/knowledge-base/03-aegisbox.md)

## Build & Test Commands
- **Build CLI & Daemon:** `go build -o bin/aegisbox ./cmd/aegisbox && go build -o bin/aegisboxd ./cmd/aegisboxd`
- **Unit Tests:** `go test -v ./...`
- **Adversarial Range Tests:** `go test -v ./test/adversarial/...`
- **Linter:** `golangci-lint run`
- **Diagnostics:** `./bin/aegisbox doctor`
- **Execute in MicroVM:** `./bin/aegisbox exec -- <cmd>`

## Code Style & Architectural Invariants
- Unbreakable microVM boundary via libkrun / Apple Hypervisor Framework / Linux KVM.
- Host repository directory must be mounted read-only; mutations trapped in COW overlay.
- Egress strictly controlled via `pkg/netgate` with DNS pinning.
- SPIFFE SVID workload attestation required before credential leases.
- Preserves macOS `com.apple.security.hypervisor` entitlement.

## Commit Invariants
- Mandatory cryptographic signing with GPG key `7BB5B44244E586B0` (`git commit -S`).
- Present diff and test output for explicit user sign-off before committing.
