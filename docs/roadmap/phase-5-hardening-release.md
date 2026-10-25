# Phase 5: Hardening, Enterprise Controls & Production Release
## Technical Execution Specification & Engineering Work-Breakdown (Weeks 17–20)

**Status:** Completed & Verified (Exit Gate Passed)  
**Owner:** Product Security & Release Engineering  
**Dependencies:** Phase 1 through Phase 4  
**Target Repositories/Packages:** `test/`, `pkg/security`, `deploy/`, `.github/workflows`

---

## 1. Overview & Objective

Phase 5 hardens the entire Aegisbox platform against adversarial escapes, integrates enterprise fleet policy management (MDM/GPO), establishes an automated cryptographically signed release pipeline, and validates real-world performance through a multi-agent enterprise beta pilot.

**Exit Criterion:** Zero high or critical findings from continuous fuzzing suites; enterprise policy locking verified across macOS, Linux, and Windows; multi-agent execution matrices pass with zero host escapes; and production release packages (DMG, MSI, AppImage) deploy cleanly across workstation fleets.

---

## 2. Architecture & File Layout

```
aegisbox/
├── deploy/
│   ├── enterprise/
│   │   ├── macos/
│   │   │   └── com.bonjoski.aegisbox.plist     # macOS MDM Configuration Profile
│   │   ├── windows/
│   │   │   ├── aegisbox.admx                   # Windows Group Policy Administrative Template
│   │   │   └── aegisbox.adml                   # GPO Language Resource
│   │   └── linux/
│   │       └── policy.json                     # System-wide policy schema (/etc/aegisbox/)
│   └── packaging/
│       ├── wix/                                # Windows WiX MSI installer definition
│       └── macos/                              # Notarization & entitlement scripts
├── test/
│   ├── fuzz/
│   │   ├── fuzz_ipc.go                         # Go-fuzz harness for daemon IPC messages
│   │   ├── fuzz_mcp_parser.go                  # Fuzz harness for streaming JSON-RPC tokenizer
│   │   └── fuzz_vsock_frame.go                 # Fuzz harness for guest-host vsock framing
│   ├── matrix/                                 # Autonomous AI agent adversarial test range
│   │   ├── agent_claude_test.go
│   │   ├── agent_gemini_test.go
│   │   └── agent_antigravity_test.go
│   └── benchmarks/
│       └── fleet_latency_test.go               # Multi-platform boot & teardown benchmark
└── .github/
    └── workflows/
        ├── release_build.yml                   # Tri-platform signed build matrix
        └── security_audit.yml                  # Static analysis & fuzzing pipeline
```

---

## 3. Enterprise Fleet Policy Specification

Enterprise administrators can enforce non-negotiable security postures across fleets using native OS configuration managers:

### macOS Configuration Profile (`com.bonjoski.aegisbox.plist`)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>EnforceMinimumProfile</key>
    <string>MicroVMHardened</string>
    <key>DisablePermissiveMode</key>
    <true/>
    <key>AllowlistEgressDomains</key>
    <array>
        <string>*.github.com</string>
        <string>registry.npmjs.org</string>
        <string>crates.io</string>
    </array>
    <key>AuditLogForwardingEndpoint</key>
    <string>https://siem.internal.corp/aegisbox/v1/traces</string>
</dict>
</plist>
```

### Windows Group Policy (GPO Registry Keys)
* **Path:** `HKLM\SOFTWARE\Policies\Aegisbox`
  * `EnforceMinimumProfile` (DWORD): `2` (2 = MicroVM Hardened)
  * `DisablePermissiveMode` (DWORD): `1`
  * `AllowlistEgressDomains` (REG_MULTI_SZ): `*.github.com`, `registry.npmjs.org`

---

## 4. Week-by-Week Implementation Plan

### Week 17: Adversarial Security Fuzzing & Protocol Hardening
* **Tasks:**
  1. Author `test/fuzz/fuzz_ipc.go`:
     - Fuzz Unix domain socket and Windows Named Pipe listeners using random byte buffers and malformed Protobuf packets.
  2. Author `fuzz_mcp_parser.go`:
     - Fuzz streaming JSON-RPC proxy with deeply nested JSON, oversized strings, malformed unicode characters, duplicate keys, and Bidi control characters.
  3. Author `fuzz_vsock_frame.go`:
     - Fuzz vsock packet frames from guest to host to ensure no hypervisor crash or host memory corruption.
  4. Author `test/fuzz/fuzz_dns_tunnel.go`:
     - Fuzz the embedded DNS proxy with base32/base64 tunneling payloads, DNS amplification patterns, and malformed query flags.
  5. Run fuzzing clusters for 72 continuous hours.
* **Verification:** Zero panics, zero unhandled errors, and zero memory leaks under 100M+ mutations. Zero DNS queries for unlisted domains leaked upstream.

### Week 18: Enterprise Fleet Lockdown & Policy Enforcement
* **Tasks:**
  1. Implement `pkg/policy/enterprise.go`:
     - **Adversarial Policy Precedence Hierarchy:**
       Enforce non-overridable hierarchical policy resolution:
       - **Tier 1 (Immutable Machine MDM / GPO):** `/Library/Managed Preferences` (macOS), `HKLM\SOFTWARE\Policies\Aegisbox` (Windows), `/etc/aegisbox/policy.json` (Linux).
       - **Tier 2 (Workspace Policy):** `.aegisbox/policy.yaml` in repo root (can only tighten, never loosen Tier 1).
       - **Tier 3 (User Local Preference):** `~/.aegisbox/config.yaml` (subordinate to Tiers 1 and 2).
       - Any attempt by lower tiers to relax settings, disable tripwires, or enable "Permissive" mode when locked by Tier 1 immediately triggers an attestation rejection and audit event.
  2. Implement Policy Lockdown Gate:
     - When `DisablePermissiveMode` is set, completely disable the "Permissive" option in both Tauri UI and CLI.
     - Block tampering: If a user attempts to edit local config to bypass MDM, daemon rejects startup and logs an alert.
  3. Build SIEM telemetry forwarder:
     - Push signed audit logs directly to remote enterprise collector via mTLS.
* **Testing:** Apply test MDM profile; launch Tauri client; verify profile switcher is locked to "MicroVM Hardened" with administrator badge. Attempt config shadowing attack; verify lower tier overrides are ignored.

### Week 19: Tri-Platform Build Pipeline & Automated Signing
* **Tasks:**
  1. Configure GitHub Actions tri-platform release matrix (`.github/workflows/release_build.yml`):
     - `macos-14-arm64` (Apple Silicon M-series)
     - `ubuntu-24.04` (x86_64 and arm64)
     - `windows-2025` (x86_64)
  2. Implement Code Signing & Notarization:
     - macOS: Apple Developer ID signing + `gon` notarization with hardened runtime entitlements.
     - Windows: Sign Authenticode binaries and `.msi` installers using DigiCert / Azure Trusted Signing.
     - Linux: Cosign keyless container and binary signing with Sigstore.
  3. **Adversarial Auto-Updater TOCTOU Defense:**
     - Download update payloads into ephemeral directories with strict `0700` POSIX / user-only Windows DACL permissions.
     - Verify Ed25519 signature and SHA256 digest in memory *immediately before* atomic rename (`renameat2` with `RENAME_NOREPLACE` on Linux, `MoveFileEx` with `MOVEFILE_REPLACE_EXISTING` on Windows).
     - Verify binary code signature using OS trust APIs prior to launching new binary.
* **Testing:** Download generated installer artifacts on clean test machines; verify seamless installation without Gatekeeper or SmartScreen warnings. Perform man-in-the-middle payload corruption test on updater; verify bad signature halts update immediately with zero host state mutation.

### Week 20: Enterprise Beta Pilot & Multi-Agent Model-Runner Evaluation
* **Tasks:**
  1. **Automated Multi-Agent Range Evaluation via Model-Runner:**
     - Integrate `github.com/bonjoski/model-runner` as the automated evaluation harness.
     - Deploy autonomous coding agents (Claude Code, Gemini, Antigravity, OpenAI Codex) inside Aegisbox microVMs using Locksmith biometric credentials across 50 weaponized repository test cases:
       - Obfuscated reverse shells in `postinstall` scripts.
       - Canary token exfiltration attempts to `169.254.169.254`.
       - Asynchronous DNS exfiltration tunneling attempts (`<token>.attacker.com`).
       - Symlink and device node (`mknod`/FIFO) escape attacks in workspace mounts.
       - Deceptive formatting & Bidi character attacks targeting HITL approval dialogs.
       - Memory inspection attacks scanning for dirty pages from previous pooled VM snapshots.
  2. Validate Fleet Latency Metrics:
     - Cold-boot latency verified `<30ms` on Linux and `<80ms` on macOS/Windows.
     - Client idle RAM verified `<35MB` on Linux, `<60MB` on macOS, and `<70MB` on Windows.
  3. Review beta pilot feedback and finalize v1.0 Production Release.
* **Testing:** 100% of weaponized payload attacks intercepted and neutralized by Aegisbox and Argus. Zero host compromises. Zero dirty memory leaks detected across pooled instances. Zero DNS exfiltrations permitted.

---

## 5. Verification Matrix & Exit Criteria

| Test Case | Target / Threshold | Command / Verification |
| :--- | :--- | :--- |
| **Protocol Fuzzing** | Zero panics / crashes after 72 hours | `go test -fuzz=FuzzIPC -fuzztime=72h ./test/fuzz` |
| **Enterprise Policy Lock** | 100% enforcement of minimum profile | Profile toggle to Permissive blocked when MDM key present. |
| **Multi-Agent Escape Rate** | `0%` escape rate (100% containment) | `go test -v ./test/matrix/...` passes all 50 escape scenarios. |
| **macOS Notarization** | Valid Apple Ticket attached | `spctl --assess --type execute -v Aegisbox.app` returns `accepted`. |
| **Windows Authenticode** | Valid digital signature verified | `Get-AuthenticodeSignature aegisbox.msi` returns `Valid`. |
| **Fleet Cold Boot Latency** | `<30ms` (Linux) / `<80ms` (macOS/Win) | Automated benchmark suite runs across fleet workstations. |
