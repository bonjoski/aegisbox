# Phase 4: Observability UI, Offscreen Canvas & Audit Pipeline
## Technical Execution Specification & Engineering Work-Breakdown (Weeks 13–16)

**Status:** Completed & Verified (Exit Gate Passed)  
**Owner:** Observability & Frontend Performance Engineering  
**Dependencies:** Phase 3 (Tauri Desktop Core)  
**Target Repositories/Packages:** `desktop/src/`, `pkg/telemetry`, `pkg/audit`

---

## 1. Overview & Objective

Phase 4 delivers the high-throughput observability console and forensic auditing engine. It builds a high-performance streaming visualizer for intercepted MCP tool calls, active egress connections, and canary tripwire alerts. To prevent JavaScript heap explosion and maintain low memory footprints during heavy build logs, rendering is offloaded to an **OffscreenCanvas ring buffer engine**.

**Exit Criterion:** The observability console renders streaming tool-call graphs and network egress maps under high-frequency load (10,000 lines/sec) with `<5ms` UI latency, while maintaining strict memory ceilings (<60MB on Linux, <85MB on macOS WKWebView, <90MB on Windows WebView2).

---

## 2. Architecture & File Layout

```
aegisbox/
├── desktop/
│   └── src/
│       ├── lib/
│       │   ├── canvas/
│       │   │   ├── LogRingBuffer.ts         # High-speed circular memory buffer
│       │   │   ├── CanvasRenderer.worker.ts # Dedicated Web Worker with OffscreenCanvas
│       │   │   └── GraphLayout.ts           # Lightweight DAG visualizer for tool calls
│       │   ├── components/
│       │   │   ├── ObservabilityConsole.svelte # Main split-pane observability view
│       │   │   ├── LiveNetworkMap.svelte       # Real-time egress & tripwire topology
│       │   │   ├── ToolCallGraph.svelte        # Visual DAG of agent actions
│       │   │   └── AuditExportModal.svelte     # Cryptographic export dialog
│       │   └── stores/
│       │       └── telemetryStore.svelte.ts    # Streaming telemetry rune store
└── pkg/
    ├── telemetry/
    │   ├── ringbuffer.go            # Host-side non-blocking lockless ring buffer
    │   ├── collector.go             # MicroVM stats, CPU/RAM quotas, network egress
    │   └── streamer.go              # Tauri IPC streaming channel publisher
    └── audit/
        ├── signer.go                # Ed25519 trace signing engine
        ├── schema.go                # JSONL audit event schema
        └── exporter.go              # SIEM / Splunk / Datadog export formatter
```

---

## 3. High-Throughput Canvas Architecture

```
┌────────────────────────────────┐
│   aegisboxd Telemetry Stream   │
│   (Logs, MCP calls, Egress)    │
└───────────────┬────────────────┘
                │ IPC Chunk Stream (<2ms)
                ▼
┌────────────────────────────────┐
│   Tauri Rust Bridge Channel    │
│   (tauri::ipc::Channel)        │
└───────────────┬────────────────┘
                │ Structured Binary Frame
                ▼
┌────────────────────────────────────────────────────────┐
│             Web Worker (OffscreenCanvas)               │
│  ┌───────────────────────┐   ┌──────────────────────┐  │
│  │ LogRingBuffer (Array) │   │ Offscreen 2D Context │  │
│  │ (Max 5,000 entries)   │   │ (Zero DOM nodes)     │  │
│  └───────────┬───────────┘   └───────────┬──────────┘  │
└──────────────┼───────────────────────────┼─────────────┘
               │ requestAnimationFrame()   │
               ▼                           ▼
┌────────────────────────────────────────────────────────┐
│                   Desktop Viewport                     │
│         (Single <canvas> element in Svelte UI)         │
└────────────────────────────────────────────────────────┘
```

---

## 4. Week-by-Week Implementation Plan

### Week 13: Host Telemetry Collector & High-Throughput Streamer
* **Tasks:**
  1. Implement `pkg/telemetry/collector.go`:
     - Collect per-microVM stats: CPU percentage, private RSS, active socket count, and Virtio-FS I/O ops.
     - Intercept package manager egress endpoints and resolve remote IP to domain name.
  2. **Adversarial Log Flooding Defense & Priority Multiplexing:**
     - Split host telemetry into two isolated channels:
       - **Priority Control Channel:** Intercept events, canary tripwire alerts, and policy decisions are delivered immediately via high-priority queues with zero drop.
       - **Console Stream Channel:** Standard stdout/stderr logs run over a bounded token bucket. If a rogue workload generates >20,000 lines/sec (`yes` loop), backpressure engages at the vsock boundary, dropping excess debug lines to prevent UI starvation.
  3. Implement `pkg/telemetry/ringbuffer.go`:
     - Lockless ring buffer on host to prevent blocking microVM execution when UI is paused or backgrounded.
  4. Wire Tauri v2 `Channel` in `desktop/src-tauri/src/commands/telemetry.rs`:
     - Push structured frames to frontend over Tauri channel.
* **Testing:** Benchmark host telemetry throughput. Stream 50,000 events/sec through collector with <1% CPU overhead. Flood console channel while firing a canary tripwire alert; verify tripwire alert is received within <2ms with zero packet drop.

### Week 14: OffscreenCanvas Worker & Virtualized Log View
* **Tasks:**
  1. Implement `desktop/src/lib/canvas/LogRingBuffer.ts`:
     - Pre-allocated typed array buffer holding up to 5,000 log lines in memory.
     - Automatic eviction of oldest entries without triggering JS garbage collection pauses.
  2. Implement `CanvasRenderer.worker.ts`:
     - OffscreenCanvas 2D rendering pipeline for virtualized text output.
     - **Adversarial ANSI Sanitizer & Terminal Echo Suppression:**
       - Strip all dangerous control sequences: OSC 52 (clipboard exfiltration/injection), OSC 0/2 (window title manipulation), DCS, and dynamic cursor manipulation sequences (preventing rogue scripts from overwriting previous log lines).
       - Whitelist strictly standard SGR formatting codes (`\x1b[[0-9;]*m` for foreground/background colors and bold/dim styling).
       - **Terminal Query Echo Suppression:** Disable all automatic terminal response features. When an agent emits terminal probe queries (`\x1b[c` Device Attributes, `\x1b[6n` Cursor Position Report, `\x1b]11;?` Background Color Query), the canvas renderer MUST NEVER emit synthetic responses back into the input stream. This completely neutralizes PTY/terminal echo command-injection attacks.
     - Support search text highlighting and hardware-accelerated scrolling.
  3. Build `desktop/src/lib/components/ObservabilityConsole.svelte`:
     - Embed virtualized canvas viewport with filter bar (stdout, stderr, MCP tool calls, egress alerts).
* **Testing:** Stream continuous synthetic terminal output at 10,000 lines/sec containing weaponized OSC 52 clipboard commands; verify that clipboard remains untouched and private RSS remains strictly under allocated ceiling.

### Week 15: Real-Time MCP Tool-Call Graph & Network Egress Map
* **Tasks:**
  1. Implement `GraphLayout.ts`:
     - Incremental directed acyclic graph (DAG) layout engine showing agent tool execution trees:
       `Agent Prompt ➔ read_file ➔ ast_vet ➔ run_command (npm test) ➔ write_file`.
  2. Implement `LiveNetworkMap.svelte`:
     - Real-time connection visualizer grouping outbound packets by destination domain.
     - High-visibility red pulse indicator when a Canary IP tripwire (e.g. `169.254.169.254`) is touched.
  3. Add click-to-inspect modal: Click any node in the graph to inspect exact JSON-RPC request and response payloads.
* **Testing:** Run multi-step agent workflow (50+ actions); verify DAG renders without layout jitter or dropped frames.

### Week 16: Cryptographic Audit Export & Forensic Packaging
* **Tasks:**
  1. Implement `pkg/audit/signer.go`:
     - **Hardware-Backed Key Protection:**
       - Generate Ed25519 signing keypair backed by native hardware keystores:
         - macOS: Secure Enclave / Apple Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
         - Windows: Windows CNG / TPM 2.0 provider (`NCryptCreatePersistedKey`).
         - Linux: TPM 2.0 / system-level Secret Service.
       - Reject storing unencrypted private keys in plaintext files on host filesystem.
     - **Cryptographic Hash-Chained Audit Log:**
       - Every audit record contains: `sequence_num`, `timestamp_utc`, `prev_record_hash_sha256`, `event_payload`, and `cumulative_signature`.
       - Forms an append-only, tamper-evident hash chain. Any omitted, deleted, or reordered log frame invalidates the cryptographic signature of all subsequent entries.
     - Sign entire session trace JSONL artifact with SHA256 digest and Ed25519 signature block.
  2. Implement `exporter.go`:
     - Formats: Signed JSONL, SARIF (for GitHub Code Scanning integration), and OpenTelemetry OTLP format for Splunk/Datadog.
  3. Build `AuditExportModal.svelte`:
     - Export dialog allowing single-click download of cryptographically sealed audit bundle.
* **Testing:** Export session trace; verify signature using `openssl` / `cosign` and validate checksum against all recorded microVM state changes. Test deleting a single middle log line from the JSONL export; verify cryptographic hash chain verification immediately reports tampering at that exact sequence number. Verify private key is non-exportable from OS secure keystore.

---

## 5. Verification Matrix & Exit Criteria

| Test Case | Target / Threshold | Command / Verification |
| :--- | :--- | :--- |
| **Streaming UI Latency** | `<5ms` render latency under 10k lines/sec | Profile via Chrome DevTools Performance timeline. |
| **Active Streaming Memory (Linux)** | `<60MB` RSS | Linux `smem` / `ps -o rss` under continuous 10k lines/sec log burst. |
| **Active Streaming Memory (macOS)** | `<85MB` RSS | Activity Monitor WebProcess RSS under continuous log streaming. |
| **Active Streaming Memory (Windows)**| `<90MB` RSS | Windows Task Manager Private Working Set during log burst. |
| **DAG Render Overhead** | 60 FPS maintained during graph updates | Zero frame drops measured via requestAnimationFrame FPS counter. |
| **Audit Verification** | 100% cryptographic validity | `cosign verify-blob` succeeds against exported session bundle. |
