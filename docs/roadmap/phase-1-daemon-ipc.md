# Phase 1: Daemon, Privileged Network Helper & IPC Foundation
## Technical Execution Specification & Engineering Work-Breakdown (Weeks 1–4)

**Status:** ✅ COMPLETED & VERIFIED (Weeks 1–4 Delivered)  
**Owner:** Core Systems Engineering  
**Dependencies:** None (Foundational Phase)  
**Target Repositories/Packages:** `cmd/aegisboxd`, `cmd/aegisbox-netd`, `pkg/ipc`, `pkg/vmm`

---

## 1. Overview & Objective

Phase 1 establishes the headless server-client architecture of Aegisbox. It decouples the long-running virtualization and policy engine (`aegisboxd`) from unprivileged CLI/GUI clients, introduces the minimal privileged network helper (`aegisbox-netd`), and implements secure, cross-platform local IPC across Linux, macOS, and Windows.

**Exit Criterion:** Unprivileged CLI client initiates, streams telemetry from, and cleanly terminates microVM instances in `<30ms` (Linux KVM) and `<80ms` (macOS VZ / Windows HCS) via local IPC with zero persistent root execution for `aegisboxd`.

---

## 2. Architecture & File Layout

```
aegisbox/
├── api/
│   └── proto/
│       ├── v1/
│       │   ├── daemon.proto         # Protobuf definitions for client-daemon IPC
│       │   └── netd.proto           # Protobuf definitions for daemon-netd IPC
├── cmd/
│   ├── aegisbox/                    # Unprivileged CLI client (IPC client mode)
│   ├── aegisboxd/                   # Headless orchestration daemon
│   │   ├── main.go
│   │   ├── server.go                # gRPC / Protobuf socket server
│   │   └── supervisor.go            # MicroVM process supervisor & pool manager
│   └── aegisbox-netd/               # Privileged helper daemon (root/LocalSystem)
│       ├── main.go
│       ├── helper_linux.go          # CAP_NET_ADMIN TAP & nftables
│       ├── helper_darwin.go         # pfctl ephemeral anchors
│       └── helper_windows.go        # Windows Filtering Platform (WFP)
└── pkg/
    ├── ipc/
    │   ├── client.go                # Client IPC connection & reconnect engine
    │   ├── transport_unix.go        # POSIX 0600 UDS + SO_PEERCRED / LOCAL_PEERPID
    │   ├── transport_windows.go     # Named pipe + User SID DACL
    │   └── auth.go                  # Ephemeral session token negotiation
    └── vmm/
        ├── pool.go                  # Pre-warmed microVM pool manager
        └── snapshot.go              # Hypervisor snapshot restore abstractions
```

---

## 3. IPC Schema & Protobuf Definition (`api/proto/v1/daemon.proto`)

```protobuf
syntax = "proto3";

package aegisbox.daemon.v1;

option go_package = "github.com/bonjoski/aegisbox/pkg/ipc/v1;ipcv1";

service AegisboxDaemonService {
  // Session & Authentication
  rpc Handshake(HandshakeRequest) returns (HandshakeResponse);
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);

  // MicroVM Lifecycle
  rpc StartVM(StartVMRequest) returns (StartVMResponse);
  rpc StopVM(StopVMRequest) returns (StopVMResponse);
  rpc ListVMs(ListVMsRequest) returns (ListVMsResponse);
  rpc StreamVMConsole(StreamVMConsoleRequest) returns (stream VMConsoleChunk);

  // Tool Call & Policy Interception
  rpc InterceptToolCall(InterceptToolCallRequest) returns (InterceptToolCallResponse);
  rpc SubmitApprovalDecision(ApprovalDecisionRequest) returns (ApprovalDecisionResponse);

  // Observability & Telemetry Streaming
  rpc StreamTelemetry(StreamTelemetryRequest) returns (stream TelemetryFrame);
}

message HandshakeRequest {
  string client_version = 1;
  uint32 client_pid = 2;
  string client_platform = 3;
}

message HandshakeResponse {
  string session_token = 1;
  string daemon_version = 2;
  repeated string supported_features = 3;
}

message StartVMRequest {
  string profile = 1; // "permissive", "standard", "microvm-hardened"
  string workspace_path = 2;
  repeated string allowed_egress_domains = 3;
  int32 vcpu_count = 4;
  int32 memory_mb = 5;
  bool use_snapshot_pool = 6;
}

message StartVMResponse {
  string vm_id = 1;
  uint32 vsock_port = 2;
  int64 startup_latency_us = 3;
}

message StopVMRequest {
  string vm_id = 1;
  bool force = 2;
  bool discard_cow_overlay = 3;
}

message StopVMResponse {
  bool success = 1;
  int32 exit_code = 2;
  string failure_reason = 3;
}

message StreamVMConsoleRequest {
  string vm_id = 1;
}

message VMConsoleChunk {
  bytes data = 1;
  bool is_stderr = 2;
  int64 timestamp_ns = 3;
}
```

---

## 4. Week-by-Week Implementation Plan

### Week 1: Protobuf Schema, Codegen & IPC Transports
* **Tasks:**
  1. Author `api/proto/v1/daemon.proto` and `api/proto/v1/netd.proto`.
  2. Configure `buf.yaml` and `buf.gen.yaml` for Go and Rust code generation.
  3. Implement `pkg/ipc/transport_unix.go`:
     - Bind Unix domain socket at `~/.aegisbox/aegisboxd.sock`.
     - **Adversarial Directory Guard:** Check `lstat()` on `~/.aegisbox`; abort if it is a symlink or permissions are looser than `0700`. Socket file is created with POSIX `0600`.
     - **PID-Reuse Race Defense:** 
       - On Linux: Enforce `SO_PEERCRED` (`syscall.GetsockoptUcred`) validating that caller `UID` and `GID` match the daemon process.
       - On macOS: Reject relying solely on `LOCAL_PEERPID` (susceptible to rapid PID rollover). Instead, query `LOCAL_PEERCRED` (`xucred`) and verify `cr_uid == getuid()`. For auditing, extract caller audit token via `LOCAL_PEERTOKEN` / `audit_token_to_pid`.
  4. Implement `pkg/ipc/transport_windows.go`:
     - Bind Windows Named Pipe at `\\.\pipe\aegisboxd`.
     - Construct Security Descriptor using SDDL `D:(A;;GRGW;;;<UserSID>)` strictly granting access only to the invoking user SID.
     - **PID-Reuse Race Defense:** Call `ImpersonateNamedPipeClient()` followed by `OpenThreadToken()` and `GetTokenInformation(TokenUser)` to extract the caller's verified SID. Do not rely on unprivileged userland process ID lookups.
  5. Implement **DoS & Resource Quota Guards**:
     - Limit concurrent microVM instances per UID (default max 3).
     - Rate-limit incoming IPC connection attempts (token bucket: 20 req/sec, burst 50).
* **Testing:** Unit test IPC socket handshakes on Linux, macOS, and Windows. Verify that cross-user connection attempts are immediately rejected.

### Week 2: `aegisboxd` Daemon Core & Process Supervisor
* **Tasks:**
  1. Implement `cmd/aegisboxd/main.go` supporting flags: `--socket-path`, `--config`, `--foreground`, and `--systemd`.
  2. Build `cmd/aegisboxd/supervisor.go`:
     - Abstract VM handles with tracking for active microVM instances, workspace bindings, and vsock ports.
     - **Adversarial Memory Isolation & Snapshot Cross-Contamination Defense:**
       - All pooled microVM snapshots MUST be backed by private copy-on-write memory mappings (`MAP_PRIVATE` with anonymous memory or dedicated backing files).
       - When a microVM instance is terminated, its memory mappings are immediately unmapped and purged using `madvise(..., MADV_DONTNEED)` or explicitly zeroed before handle release. No dirty guest RAM pages are ever shared between successive microVM instances.
     - **Monotonic Host-Only Time Assertion:**
       - All token expiry calculations, session leases, and rate-limit windows MUST use host monotonic time (`CLOCK_MONOTONIC_RAW`). Never rely on guest-asserted timestamps or allow in-guest clock changes (`settimeofday`) to extend token lifetimes.
     - Implement pre-warmed snapshot pool: Maintain 1–2 paused microVM instances ready in memory.
     - Add `virtio-rng` seed re-injection upon pool unpause.
  3. Implement graceful shutdown handler: When SIGINT/SIGTERM is received, cleanly abort running VMs and wipe temporary vsock mounts.
* **Testing:** Launch `aegisboxd`, issue mock gRPC `StartVM` requests via `grpcurl`, verify microVM allocation and cleanup. Run memory diff inspection between successive pooled microVM runs; verify 0 bytes of residual memory bleed.

### Week 3: Privileged Network Helper (`aegisbox-netd`)
* **Tasks:**
  1. Implement `cmd/aegisbox-netd/main.go` listening strictly on a root-owned Unix socket (`/var/run/aegisbox-netd.sock`, mode `0600`) or Windows Named Pipe (`\\.\pipe\aegisbox-netd`).
  2. **Privileged Interface Defense & Input Hardening:**
     - Reject raw shell execution or string interpolation in all firewall invocations.
     - Validate interface names against strict regex: `^aegis-tap[0-9]{1,4}$`.
     - Validate egress domains and CIDRs using Go's `net/netip` before creating rules.
     - Reject requests from any caller UID other than the pre-registered `aegisboxd` UID.
  3. Implement `helper_linux.go`:
     - TAP interface allocation and assignment to the unprivileged UID running `aegisboxd`.
     - Insert ephemeral `nftables` tables scoped to the microVM TAP interface.
     - Canary IP sinkholing for `169.254.169.254`.
  4. Implement `helper_darwin.go`:
     - Dynamic ephemeral `pfctl` anchor insertion (`anchor "aegisbox/*"`).
  5. Implement `helper_windows.go`:
     - WFP filter registration binding the Hyper-V virtual switch port.
* **Testing:** Benchmark network setup latency. Ensure helper operations complete in `<5ms`. Perform fuzzing on `aegisbox-netd` RPC interface with invalid interface names and malformed IP strings; verify all are rejected with `InvalidArgument`.

### Week 4: Unprivileged CLI Parity & End-to-End Latency Verification
* **Tasks:**
  1. Refactor `cmd/aegisbox/cmd_exec.go` to use the gRPC client in `pkg/ipc`.
  2. Add automatic daemon autostart: If `aegisboxd.sock` does not respond, unprivileged CLI starts `aegisboxd` in background before connecting.
  3. Implement CLI commands: `aegisbox daemon status`, `aegisbox daemon stop`, and `aegisbox vm list`.
  4. Run microVM cold-start benchmarks across all platforms.
* **Verification Command:**
  ```bash
  go test -v -bench=BenchmarkVMBoot -benchtime=50x ./pkg/vmm/...
  ```

---

## 5. Verification Matrix & Exit Criteria

| Test Case | Target / Threshold | Command / Verification |
| :--- | :--- | :--- |
| **Linux Boot Latency** | `<30ms` (cold start from snapshot pool) | `go test -run=TestSnapshotPoolLatency_Linux -v ./pkg/vmm` |
| **macOS Boot Latency** | `<80ms` (Apple VZ unpause) | `go test -run=TestSnapshotPoolLatency_Darwin -v ./pkg/vmm` |
| **Windows Boot Latency** | `<80ms` (HCS utility VM unpause) | `go test -run=TestSnapshotPoolLatency_Windows -v ./pkg/vmm` |
| **IPC Round-Trip** | `<2ms` overhead | `go test -bench=BenchmarkIPCRoundtrip ./pkg/ipc` |
| **Cross-User Rejection** | 100% blocked | Socket connection test under secondary UID fails with `EACCES`. |
