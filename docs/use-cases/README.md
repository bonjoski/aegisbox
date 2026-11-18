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
