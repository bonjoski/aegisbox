export type SecuritySeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type SecurityProfile = "permissive" | "standard" | "microvm-hardened";

export type ApprovalScope = "ONCE" | "SESSION" | "WORKSPACE";

export type ApprovalDecision = "APPROVE" | "DENY";

export interface PendingApproval {
  interceptId: string;
  vmId: string;
  toolName: string;
  toolArgsJson: string;
  severity: SecuritySeverity;
  reason: string;
  timestampNs: number;
}

export interface SecurityProfileStatus {
  activeProfile: SecurityProfile;
  mdmLocked: boolean;
}

export interface TelemetryFrame {
  timestampNs: number;
  vmId: string;
  cpuPercent: number;
  memoryRssBytes: number;
  virtiofsReadBytes: number;
  virtiofsWriteBytes: number;
  activeEgress: EgressConnection[];
  canaryTriggered: boolean;
  canaryTargetIp?: string;
}

export interface EgressConnection {
  destinationDomain: string;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  bytesSent: number;
  bytesReceived: number;
  isPinned: boolean;
}
