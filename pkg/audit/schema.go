package audit

import (
	"encoding/json"
	"time"
)

// AuditEventType identifies the type of security or execution event.
type AuditEventType string

const (
	AuditEventVMStart       AuditEventType = "VM_START"
	AuditEventVMStop        AuditEventType = "VM_STOP"
	AuditEventMCPToolCall   AuditEventType = "MCP_TOOL_CALL"
	AuditEventMCPDecision   AuditEventType = "MCP_DECISION"
	AuditEventEgressBlock   AuditEventType = "EGRESS_BLOCK"
	AuditEventTripwireAlert AuditEventType = "TRIPWIRE_ALERT"
	AuditEventCoWCommit     AuditEventType = "COW_COMMIT"
)

// AuditRecord represents an immutable, hash-chained log entry.
type AuditRecord struct {
	SequenceNum          uint64         `json:"sequence_num"`
	TimestampUTC         string         `json:"timestamp_utc"`
	PrevRecordHashSHA256 string         `json:"prev_record_hash_sha256"`
	EventType            AuditEventType `json:"event_type"`
	VMID                 string         `json:"vm_id"`
	PayloadJSON          string         `json:"payload_json"`
	RecordHashSHA256     string         `json:"record_hash_sha256"`
	Signature            string         `json:"signature"`
}

// SessionAuditBundle contains the complete exported session trace.
type SessionAuditBundle struct {
	SessionID         string        `json:"session_id"`
	StartedAt         time.Time     `json:"started_at"`
	EndedAt           time.Time     `json:"ended_at"`
	PublicKeyBase64   string        `json:"public_key_base64"`
	GenesisHashSHA256 string        `json:"genesis_hash_sha256"`
	FinalHashSHA256   string        `json:"final_hash_sha256"`
	Records           []AuditRecord `json:"records"`
}

// MarshalJSON returns canonical formatted JSON bytes.
func (r *AuditRecord) MarshalJSON() ([]byte, error) {
	type Alias AuditRecord
	return json.Marshal((*Alias)(r))
}
