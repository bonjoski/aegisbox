package audit

import (
	"strings"
	"testing"
)

func TestAuditSigner_ValidChain(t *testing.T) {
	signer, err := NewAuditSigner("session-alpha-1")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	_, err = signer.AppendEvent(AuditEventVMStart, "vm-01", `{"profile":"microvm-hardened"}`)
	if err != nil {
		t.Fatalf("failed to append event 1: %v", err)
	}

	_, err = signer.AppendEvent(AuditEventMCPToolCall, "vm-01", `{"tool":"read_file","path":"/src/main.go"}`)
	if err != nil {
		t.Fatalf("failed to append event 2: %v", err)
	}

	_, err = signer.AppendEvent(AuditEventCoWCommit, "vm-01", `{"files_changed":3}`)
	if err != nil {
		t.Fatalf("failed to append event 3: %v", err)
	}

	bundle := signer.ExportBundle()
	if len(bundle.Records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(bundle.Records))
	}

	valid, tamperedSeq, err := VerifyAuditBundle(bundle)
	if err != nil || !valid {
		t.Fatalf("expected valid bundle verification, got valid=%v, seq=%d, err=%v", valid, tamperedSeq, err)
	}
}

func TestAuditSigner_DetectTamperedPayload(t *testing.T) {
	signer, err := NewAuditSigner("session-tamper-test")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	_, _ = signer.AppendEvent(AuditEventVMStart, "vm-01", `{"action":"boot"}`)
	_, _ = signer.AppendEvent(AuditEventMCPToolCall, "vm-01", `{"tool":"read_file"}`)
	_, _ = signer.AppendEvent(AuditEventVMStop, "vm-01", `{"action":"shutdown"}`)

	bundle := signer.ExportBundle()

	// Tamper with record #2's payload
	bundle.Records[1].PayloadJSON = `{"tool":"rm -rf /"}`

	valid, tamperedSeq, err := VerifyAuditBundle(bundle)
	if valid {
		t.Fatalf("expected tampered bundle to FAIL verification, but passed")
	}

	if tamperedSeq != 2 {
		t.Errorf("expected tamper detection at sequence 2, got %d (err: %v)", tamperedSeq, err)
	}
}

func TestAuditSigner_DetectDeletedRecord(t *testing.T) {
	signer, err := NewAuditSigner("session-deletion-test")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	_, _ = signer.AppendEvent(AuditEventVMStart, "vm-01", `{"seq":1}`)
	_, _ = signer.AppendEvent(AuditEventTripwireAlert, "vm-01", `{"canary":"169.254.169.254"}`)
	_, _ = signer.AppendEvent(AuditEventVMStop, "vm-01", `{"seq":3}`)

	bundle := signer.ExportBundle()

	// Adversary attempts to delete the tripwire alert record (#2)
	bundle.Records = []AuditRecord{bundle.Records[0], bundle.Records[2]}

	valid, tamperedSeq, err := VerifyAuditBundle(bundle)
	if valid {
		t.Fatalf("expected deleted record to break chain, but verification passed")
	}

	t.Logf("Detected chain breakage at sequence %d: %v", tamperedSeq, err)
}

func TestAuditExporter_JSONL_SARIF_OTLP(t *testing.T) {
	signer, err := NewAuditSigner("session-export-test")
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	_, _ = signer.AppendEvent(AuditEventVMStart, "vm-01", `{"profile":"standard"}`)
	_, _ = signer.AppendEvent(AuditEventTripwireAlert, "vm-01", `{"probe":"aws-metadata"}`)

	bundle := signer.ExportBundle()

	// 1. JSONL Export
	jsonlBytes, err := ExportJSONL(bundle)
	if err != nil {
		t.Fatalf("failed JSONL export: %v", err)
	}
	if !strings.Contains(string(jsonlBytes), "aegisbox_audit_version") {
		t.Errorf("expected version header in JSONL")
	}

	// 2. SARIF Export
	sarifBytes, err := ExportSARIF(bundle)
	if err != nil {
		t.Fatalf("failed SARIF export: %v", err)
	}
	if !strings.Contains(string(sarifBytes), "sarif-schema-2.1.0") {
		t.Errorf("expected SARIF schema declaration")
	}

	// 3. OTLP Export
	otlpBytes, err := ExportOTLP(bundle)
	if err != nil {
		t.Fatalf("failed OTLP export: %v", err)
	}
	if !strings.Contains(string(otlpBytes), "resourceLogs") {
		t.Errorf("expected OTLP resourceLogs")
	}
}
