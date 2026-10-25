# Phase 3: Tauri Desktop Core, Multiplatform Tray & CLI Parity
## Technical Execution Specification & Engineering Work-Breakdown (Weeks 9–12)

**Status:** Completed & Verified (Exit Gate Passed)  
**Owner:** Desktop & User Experience Engineering  
**Dependencies:** Phase 1 (Daemon IPC) & Phase 2 (MCP Firewall & Approvals)  
**Target Repositories/Packages:** `desktop/`, `cmd/aegisbox`, `pkg/ipc`

---

## 1. Overview & Objective

Phase 3 builds the primary developer presentation and control interface: the **Tauri v2 Desktop Application** paired with complete **Headless CLI Parity**. It delivers the system tray quick-switcher, the Human-in-the-Loop (HITL) intercept modal with fatigue mitigation scoping, and unifies desktop UX across macOS (`WKWebView`), Linux (`WebKitGTK`), and Windows (`WebView2`).

**Exit Criterion:** Developers can switch security profiles with a single click from the system tray, review and approve intercepted tool calls in <50ms with session scoping, and execute the exact same workflows headlessly over SSH or CI via `aegisbox approve`.

---

## 2. Architecture & File Layout

```
aegisbox/
├── desktop/
│   ├── src-tauri/
│   │   ├── Cargo.toml               # Tauri v2 dependencies
│   │   ├── tauri.conf.json          # App config, permissions, tray definitions
│   │   ├── capabilities/
│   │   │   └── default.json         # Strict Tauri v2 capability definitions
│   │   └── src/
│   │       ├── main.rs              # Application entrypoint
│   │       ├── lib.rs               # Tauri builder & plugin initialization
│   │       ├── ipc_client.rs        # Rust client to aegisboxd (UDS / Named Pipe)
│   │       ├── tray.rs              # System tray icon, menu & state updates
│   │       └── commands/
│   │           ├── approvals.rs     # Rust commands for approving/rejecting tool calls
│   │           ├── profiles.rs      # Rust commands for switching security profiles
│   │           └── telemetry.rs     # Streaming IPC channel to Svelte UI
│   ├── src/
│   │   ├── App.svelte               # Root Svelte 5 application shell
│   │   ├── app.css                  # TailwindCSS directives
│   │   ├── lib/
│   │   │   ├── components/
│   │   │   │   ├── ApprovalModal.svelte     # HITL intercept sheet with scoping
│   │   │   │   ├── ProfileSwitcher.svelte   # Tray quick switcher
│   │   │   │   ├── StatusBadge.svelte       # MicroVM state & latency indicator
│   │   │   │   └── NotificationToast.svelte # Auto-dismiss status toasts
│   │   │   ├── stores/
│   │   │   │   ├── approvalStore.svelte.ts  # Svelte 5 reactive rune store
│   │   │   │   └── profileStore.svelte.ts   # Profile state & MDM lock store
│   │   │   └── types/
│   │   │       └── ipc.ts                   # TypeScript types matching Protobuf
│   ├── package.json
│   └── vite.config.ts
└── cmd/aegisbox/
    ├── cmd_approve.go               # Headless CLI approval command
    └── cmd_profile.go               # Headless profile switcher
```

---

## 3. Human-in-the-Loop (HITL) State Machine

```
               ┌───────────────────────────────┐
               │    Intercept Event Arrives    │
               │   (CEL Match: INTERCEPT_REQ)  │
               └───────────────┬───────────────┘
                               │
                               ▼
               ┌───────────────────────────────┐
               │ MicroVM Execution Suspended   │
               │ (vsock pause signal emitted)  │
               └───────────────┬───────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
 ┌──────────────────────┐              ┌──────────────────────┐
 │  Tauri Desktop Modal │              │   Headless CLI Hook  │
 │ (High-priority sheet)│              │  (aegisbox approve)  │
 └──────────┬───────────┘              └──────────┬───────────┘
            │                                     │
            └──────────────────┬──────────────────┘
                               │
     ┌─────────────────────────┼─────────────────────────┐
     ▼                         ▼                         ▼
┌─────────┐             ┌─────────────┐            ┌───────────┐
│ APPROVE │             │    DENY     │            │  TIMEOUT  │
└────┬────┘             └──────┬──────┘            └─────┬─────┘
     │                         │                         │
     ├─► Once                  ├─► Abort Tool Call       └─► Auto-Quarantine
     ├─► Session               └─► Terminate Workload        (Pause or Kill)
     └─► Workspace
```

---

## 4. Week-by-Week Implementation Plan

### Week 9: Tauri v2 Scaffold & Multiplatform Rust IPC Bridge
* **Tasks:**
  1. Initialize Tauri v2 application using Svelte 5 and Vite.
  2. Implement `desktop/src-tauri/src/ipc_client.rs`:
     - Rust client connecting to `~/.aegisbox/aegisboxd.sock` (Linux/macOS) or `\\.\pipe\aegisboxd` (Windows).
     - Perform handshake, validate daemon version, and maintain auto-reconnect backoff thread.
  3. Configure Tauri v2 capabilities (`capabilities/default.json`):
     - Strip all ambient webview privileges (`fs:*`, `shell:*`, `http:*`).
     - Expose strictly custom commands: `approve_tool_call`, `reject_tool_call`, `set_active_profile`.
* **Testing:** Run Tauri app in dev mode (`cargo tauri dev`), verify successful connection to running `aegisboxd` on macOS, Linux, and Windows.

### Week 10: Fabrial Multi-Tier Tray Switcher & Airlock Integration
* **Tasks:**
  1. Implement `desktop/src-tauri/src/tray.rs`:
     - Cross-platform system tray icon indicating active Fabrial security posture:
       - 🟢 *Green:* MicroVM Hardened (Aegisbox Tier 2)
       - 🟡 *Yellow:* Standard Local Sandbox (Airlock Tier 1: Seatbelt/Landlock)
       - ⚪ *Gray:* Permissive (Logging Only)
     - Tray menu items for profile switching, active microVM count, and console toggle.
  2. **Airlock Engine Delegation:**
     - When "Standard Local Sandbox" is active, delegate command containment directly to **Airlock** (`github.com/bonjoski/airlock/pkg/sandbox`), executing processes with sub-15ms kernel Seatbelt/Landlock profiles.
  3. Implement `pkg/ipc` profile change broadcast:
     - When tray selection changes, `aegisboxd` updates runtime policy dynamically.
  4. Add MDM / GPO lock enforcement:
     - If administrator policy prohibits "Permissive", disable menu option and show lock icon.
* **Testing:** Toggle profiles from the tray; verify `aegisboxd` applies changes without dropping existing microVM connections.

### Week 11: HITL Intercept Modal & Locksmith Biometric Approval UX
* **Tasks:**
  1. Implement `desktop/src/lib/components/ApprovalModal.svelte`:
     - Focused modal sheet that slides in when an intercept occurs.
     - Displays tool name, parsed arguments, target domain/filepath, and severity badge.
  2. **Adversarial Anti-Clickjacking & Input Injection Defenses:**
     - **Mandatory Dwell Timer:** Enforce an 800ms active disable delay on the "Approve" button upon modal focus. This defeats automated background scripts that attempt to steal focus and spam keystrokes (`Enter`/`Space`) or synthetic mouse clicks.
     - **Synthetic Event Rejection:** In Svelte handlers, strictly assert `event.isTrusted === true`. Reject programmatic click simulations.
     - **Indirect Prompt & Visual Deception Injection Defenses:**
       - **Deceptive Markdown Disabling:** Tool arguments and paths are rendered strictly in raw, monospaced plaintext blocks. Markdown rendering is forbidden on unvetted tool arguments (defeating payloads like `# APPROVED BY ADMIN: SAFE TO PROCEED`).
       - **Bidi (Bidirectional) Override Stripping:** All Unicode bidirectional control characters (`\u202A` through `\u202E`, `\u2066` through `\u2069`) are stripped before rendering, preventing right-to-left visual spoofing of file paths or extension cloaking (e.g. `test\u202Ecod.exe` appearing as `testexe.doc`).
       - **Homoglyph & Punycode Alert:** Domains containing mixed scripts or homoglyphs (e.g. Cyrillic `а` in `githυb.com`) are flagged with an unmistakable high-contrast warning badge.
     - **Locksmith Biometric Step-Up Authorization:** For `CRITICAL` severity actions (e.g., raw disk writes or private key accesses), trigger biometric challenge via **Locksmith** (`github.com/bonjoski/locksmith/pkg/native`):
       - macOS: Touch ID via `LocalAuthentication.framework`.
       - Windows: Windows Hello via `UserConsentVerifier`.
       - Linux: Polkit / PAM interactive prompt.
  3. Implement Fatigue Mitigation Scopes:
     - Buttons: `Allow Once`, `Allow for Session`, `Always for Workspace`, `Deny`.
     - **Scope Boundary Enforcement:** "Always for Workspace" rules are strictly tied to the canonicalized workspace root path. Broad wildcards (`.*`) are forbidden from UI rule generation.
  4. Implement Timeout & Suspension:
     - Visual 30-second countdown bar.
     - Rather than killing the agent upon timeout, send execution suspend signal, allowing the developer to resume when ready.
  5. Build Svelte 5 rune store (`approvalStore.svelte.ts`):
     - Manage pending approval queue reactively.
* **Testing:** Trigger 10 concurrent intercepts via test agent; attempt automated clickjacking via background synthetic click script; verify synthetic clicks are rejected and dwell timer blocks keystroke spamming.

### Week 12: Headless CLI Parity & Cross-Platform Packaging
* **Tasks:**
  1. Implement `cmd/aegisbox/cmd_approve.go`:
     - `aegisbox approve --last`: Approve the most recent pending intercept directly from terminal.
     - `aegisbox approve --list`: Display pending approval queue formatted as a terminal table.
     - `aegisbox run --non-interactive`: Enforce strict auto-deny for unattended CI/CD runs.
  2. Implement OS-specific packaging targets:
     - macOS: Universal `.dmg` with signed app bundle.
     - Linux: `.deb`, `.rpm`, and `.AppImage`.
     - Windows: Signed `.msi` package with WebView2 Evergreen detection.
* **Testing:** Disconnect display / launch over SSH; run test agent workload; execute approvals headlessly via `aegisbox approve`.

---

## 5. Verification Matrix & Exit Criteria

| Test Case | Target / Threshold | Command / Verification |
| :--- | :--- | :--- |
| **Tray Profile Switch Latency** | `<10ms` end-to-end | Profile switch reflects in daemon logs in <10ms. |
| **Approval Sheet Latency** | `<50ms` from daemon event to modal popup | Measured via timestamp delta in telemetry frame. |
| **Headless CLI Parity** | 100% feature coverage without display | `aegisbox approve --last` successfully unpauses suspended VM. |
| **Idle Desktop Memory (macOS)** | `<60MB` RSS | Activity Monitor / `ps -o rss` verification on macOS Sequoia. |
| **Idle Desktop Memory (Linux)** | `<35MB` RSS | `smem -P aegisbox-desktop` verification on Ubuntu/Debian. |
| **Idle Desktop Memory (Windows)** | `<70MB` RSS | Task Manager Private Working Set on Windows 11. |
