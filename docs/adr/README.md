# Aegisbox Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, microVM virtualization invariants, and hardware isolation models governing [`bonjoski/aegisbox`](https://github.com/bonjoski/aegisbox).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-ephemeral-microvm-hardware-isolation-libkrun.md)** | **Ephemeral MicroVM Hardware Isolation & Shadow Workspaces via libkrun** | `Accepted` | 2026-10-30 | `pkg/microvm`, `pkg/shadow` |

---

## Architectural Principles

1. **Hardware-Enforced Hypervisor Isolation:** Untrusted tool execution runs in dedicated, disposable Linux microVMs via macOS Hypervisor.framework and Linux KVM (`libkrun`).
2. **Ephemeral Copy-on-Write Shadow Workspaces:** Workspaces use disposable OverlayFS COW layers; changes can be inspected, vetted, or discarded in `< 5ms`.
3. **Air-Gapped Synthetic Virtual Networking:** MicroVMs operate on isolated vsock and private virtual subnets with default-deny WAN egress.
