import type { TelemetryFrame, EgressConnection } from "../types/ipc";

export interface LogItem {
  id: number;
  timestampNs: number;
  vmId: string;
  category: "stdout" | "stderr" | "mcp" | "egress" | "tripwire";
  text: string;
}

let nextGlobalLogId = 1000;

class TelemetryStore {
  // Svelte 5 reactive runes
  logs = $state<LogItem[]>([]);
  activeEgress = $state<EgressConnection[]>([]);
  canaryAlertActive = $state<boolean>(false);
  canaryTargetIp = $state<string>("");
  cpuPercent = $state<number>(0.8);
  memoryRssBytes = $state<number>(38 * 1024 * 1024);
  virtiofsOps = $state<number>(142);

  constructor() {
    const now = Date.now() * 1e6;
    this.logs = [
      {
        id: 1,
        timestampNs: now - 3500 * 1e6,
        vmId: "aegisboxd",
        category: "stdout",
        text: "Supervisor daemon v1.0.0 initialized [PID: 87958]",
      },
      {
        id: 2,
        timestampNs: now - 3000 * 1e6,
        vmId: "aegisboxd",
        category: "stdout",
        text: "Apple Virtualization framework hypervisor backend bound: Apple Silicon HVF",
      },
      {
        id: 3,
        timestampNs: now - 2500 * 1e6,
        vmId: "aegisboxd",
        category: "stdout",
        text: "MicroVM snapshot pool warm [sub-30ms cold-start ready]",
      },
      {
        id: 4,
        timestampNs: now - 2000 * 1e6,
        vmId: "aegisboxd",
        category: "mcp",
        text: "CEL security firewall rules compiled: 3 active rules (disk-shield, credential-guard, egress-pin)",
      },
      {
        id: 5,
        timestampNs: now - 1500 * 1e6,
        vmId: "aegisboxd",
        category: "egress",
        text: "Local DNS proxy listening on 127.0.0.1:53 [NXDOMAIN synthesis active]",
      },
      {
        id: 6,
        timestampNs: now - 1000 * 1e6,
        vmId: "aegisboxd",
        category: "stdout",
        text: "Locksmith biometric vault linked: Touch ID / Secure Enclave hardware binding",
      },
      {
        id: 7,
        timestampNs: now - 500 * 1e6,
        vmId: "vm-01",
        category: "mcp",
        text: "MCP tool mediation active on vsock:50051 (JSON-RPC streaming)",
      },
      {
        id: 8,
        timestampNs: now - 200 * 1e6,
        vmId: "agent-01",
        category: "tripwire",
        text: "🚨 CANARY TRIPWIRE VIOLATION: Rogue agent probed AWS/GCP metadata honeypot (169.254.169.254) — MicroVM execution frozen by kernel netgate",
      },
      {
        id: 9,
        timestampNs: now - 50 * 1e6,
        vmId: "agent-02",
        category: "tripwire",
        text: "🚨 HONEYPOT PROBE: Unauthorized egress attempted to canary IP 10.200.5.42:443 — Connection dropped & forensic snapshot captured",
      },
    ];

    this.activeEgress = [
      {
        destinationDomain: "registry.npmjs.org",
        destinationIp: "104.16.16.35",
        destinationPort: 443,
        protocol: "tls",
        bytesSent: 12400,
        bytesReceived: 456800,
        isPinned: true,
      },
      {
        destinationDomain: "github.com",
        destinationIp: "140.82.113.4",
        destinationPort: 443,
        protocol: "tls",
        bytesSent: 4890,
        bytesReceived: 32100,
        isPinned: true,
      },
      {
        destinationDomain: "crates.io",
        destinationIp: "151.101.1.187",
        destinationPort: 443,
        protocol: "tls",
        bytesSent: 1820,
        bytesReceived: 14200,
        isPinned: true,
      },
    ];
  }

  addLog(item: Omit<LogItem, "id"> & { id?: number }) {
    const newItem: LogItem = {
      ...item,
      id: ++nextGlobalLogId,
    };
    if (this.logs.length >= 2000) {
      this.logs = [...this.logs.slice(1), newItem];
    } else {
      this.logs = [...this.logs, newItem];
    }
  }

  clearLogs() {
    this.logs = [];
  }

  updateFrame(frame: TelemetryFrame) {
    this.cpuPercent = frame.cpuPercent;
    this.memoryRssBytes = frame.memoryRssBytes;
    if (frame.activeEgress && frame.activeEgress.length > 0) {
      this.activeEgress = frame.activeEgress;
    }
    if (frame.canaryTriggered) {
      this.canaryAlertActive = true;
      this.canaryTargetIp = frame.canaryTargetIp || "169.254.169.254";
    }
  }

  triggerCanary(targetIp: string) {
    this.canaryAlertActive = true;
    this.canaryTargetIp = targetIp;
  }

  clearCanaryAlert() {
    this.canaryAlertActive = false;
    this.canaryTargetIp = "";
  }
}

export const telemetryStore = new TelemetryStore();
