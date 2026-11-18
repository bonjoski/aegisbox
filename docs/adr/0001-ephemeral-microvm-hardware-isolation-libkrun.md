# ADR-0001: Ephemeral MicroVM Hardware Isolation & Shadow Workspaces via libkrun

- **Status:** Accepted
- **Date:** 2026-10-30
- **Component:** `pkg/microvm`, `pkg/shadow`
- **Deciders:** Lead Virtualization Architect & Red-Team Range Engineer

---

## 1. Context & Problem Statement

Tier 1 kernel sandboxes (Airlock) protect filesystem paths and network sockets, but they share the host kernel.
- Executing completely untrusted, potentially malicious binaries (e.g. unverified AI-generated executables, adversarial test suites, malware detonation) poses kernel privilege escalation risks.
- Developers need a way to run dangerous tests in disposable shadow environments that leave zero state on the host.

---

## 2. Decision Outcome

We built **Aegisbox**, a Tier 2 hardware isolation microVM runtime:

1. **Lightweight Hypervisor Virtualization (`libkrun`):**
   - Boots ephemeral Linux microVMs in **< 150ms** using macOS Hypervisor.framework or Linux KVM.
2. **Disposable Copy-on-Write Shadow Workspaces:**
   - Mounts the developer workspace via virtio-fs with a temporary COW overlay. The agent modifies files inside the microVM; upon exit, the developer inspects the diff (`aegisbox diff`) and chooses to commit or discard.
3. **ARTEX-Grade Adversarial Detonation Range:**
   - Provides an air-gapped synthetic range to detonate malicious exploit PoCs without risking host network or credential compromise.

---

## 3. Consequences

- **Positive:** True hardware hypervisor isolation; disposable throwaway workspaces; zero host pollution.
- **Negative:** ~150ms microVM boot latency (reserved for Tier 2 risky tasks; fast-path Tier 1 tasks use Airlock).
