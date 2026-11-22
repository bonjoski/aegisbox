# 💡 Aegisbox End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/aegisbox`](https://github.com/bonjoski/aegisbox)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Aegisbox** is a Tier 2 hardware microVM execution engine designed for untrusted autonomous AI agent tasks (compilations, arbitrary script execution, untrusted repo inspection, dependency builds). Leveraging Apple `Virtualization.framework` on macOS, KVM/libkrun on Linux, and Hyper-V on Windows, Aegisbox establishes a hardware hypervisor isolation boundary around executing code.

This directory provides concrete, task-oriented recipes for common developer and DevSecOps workflows.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Isolation Engine |
| :--- | :--- | :--- | :--- |
| **[01. Untrusted Repository Detonation](01-untrusted-repo-detonation.md)** | Clone, build, and explore unvetted open-source code inside a microVM with zero risk to the host OS. | `aegisbox exec --workspace ./untrusted -- <cmd>` | Hardware MicroVM |
| **[02. Copy-on-Write (COW) Shadow Workspaces](02-cow-shadow-workspaces.md)** | Give autonomous agents disposable shadow workspaces; visually inspect and diff changes before merging back to host. | `aegisbox exec --cow -- <cmd>`<br/>`aegisbox diff`<br/>`aegisbox approve` | APFS clonefile / OverlayFS |
| **[03. Interactive Visual Cockpit UI](03-cockpit-ui-inspection.md)** | Monitor microVM resource usage, inspect live terminal streaming, and review network packet drops via a local web UI. | `aegisbox cockpit --port 9090` | Web Cockpit UI |
| **[04. Multi-Agent Matrix Benchmarking](04-multi-agent-matrix-benchmarking.md)** | Concurrently benchmark competing AI agent refactoring candidates in parallel, isolated microVMs. | `aegisbox matrix --workers 4` | Concurrent MicroVM Pool |
| **[05. MCP MicroVM Server for Autonomous Agents](05-mcp-agent-sandboxing.md)** | Expose microVM execution to Claude Code, Cursor, and Antigravity over local Model Context Protocol. | `aegisbox mcp` | MCP Protocol / libkrun |
| **[06. ARTEX Machine-Speed Adversarial Range Testing](06-artex-adversarial-range-testing.md)** | Detonate machine-speed credential spraying, tenant pivot, and secret harvesting attacks against sandbox invariants. | `aegisbox test range --scenario artex-machine-speed --strict` | Adversarial Range Engine |
| **[07. 2-Minute Local Security Katas](02-two-minute-security-katas.md)** | Run 5 offline, zero-API-key interactive security katas (slopsquatting, `.env` leak, RAG hijack, MCP escalation, egress leak) with 5-line fixes. | `aegisbox learn list`<br/>`aegisbox learn kata-03-rag-injection --check` | Ephemeral `os.OpenRoot` & Offline Mock LLM |
| **[08. Unit-Testing Local AI Apps & MCP Servers](03-unit-testing-ai-apps-locally.md)** | Run 12 deterministic loopback-pinned AI-safety probes against your local HTTP RAG/chat API or STDIO MCP server. | `aegisbox test --ai-safety --target http://127.0.0.1:8080/api/chat`<br/>`aegisbox test --ai-safety --mcp-cmd "node ./dist/mcp-server.js"` | Loopback-Pinned AI-Safety Harness |
