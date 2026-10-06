# Aegisbox Examples & Reference Implementations

This directory contains real-world examples, scripts, and evaluation harnesses demonstrating how to run autonomous AI agents, security benchmarks, and model runners inside Aegisbox.

---

## Index of Examples

### 1. [Model Runner (`model-runner/`)](model-runner)
A production-ready host script wrapper (`run_model.sh`) that integrates **Locksmith** hardware-bound biometric authentication (Touch ID) with **Aegisbox** and CLI agent tools (`agi`, `agy`, `claude`, `aider`).

* **Key features**:
  * Decrypts API keys directly into host memory via Touch ID (never touching disk).
  * Automatically bounds commands to ephemeral shadow worktrees.
  * Injects agent instructions (`CLAUDE.md`, `.cursorrules`, prompt files) using `--inject`.
  * Traps shell exit to zero out host memory secrets.

---

### 2. [Empirical Sandbox Audit & Compliance Harness (`sandbox_audit_harness.py`)](sandbox_audit_harness.py)
A self-contained Python security harness designed to run *inside* the Aegisbox sandbox to empirically test defensive boundaries, verify containment, and query Gemini / Claude to produce an executive compliance audit report.

* **Key features**:
  * **Filesystem Read Probe**: Tests if access to host identity directories (`~/.ssh`, `~/.aws`, `~/.gnupg`) is denied under macOS Seatbelt.
  * **Filesystem Write Probe**: Verifies that writes to host system directories (`/Library`, `/etc`) are blocked by kernel-level Mandatory Access Control.
  * **Credential Isolation Probe**: Inspects `os.environ` to prove that the real host API key was replaced by an ephemeral synthetic loopback token (`aegis-tok-...`).
  * **Process Namespace Probe**: Confirms that process inspection (`ps`) is blocked from inspecting other host processes.
  * **LLM Compliance Synthesis**: Feeds the empirical telemetry to Gemini / Claude via the Aegisbox loopback proxy to generate a structured audit report.

#### Running the Audit Harness:
```bash
# Execute using Locksmith biometric credential on host
GEMINI_API_KEY=locksmith://GEMINI-API-KEY locksmith run -- \
  aegisbox exec \
  --allow-env=GEMINI_API_KEY \
  --inject harness.py=examples/sandbox_audit_harness.py \
  "python3 harness.py"
```
