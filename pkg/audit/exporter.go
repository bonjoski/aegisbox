package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ExportJSONL serializes the session bundle into a signed JSONL file.
// The first line is metadata/header, followed by individual hash-chained records.
func ExportJSONL(bundle *SessionAuditBundle) ([]byte, error) {
	var buf bytes.Buffer

	headerJSON, err := json.Marshal(map[string]any{
		"aegisbox_audit_version": "1.0",
		"session_id":             bundle.SessionID,
		"public_key_base64":      bundle.PublicKeyBase64,
		"genesis_hash":           bundle.GenesisHashSHA256,
		"final_hash":             bundle.FinalHashSHA256,
		"record_count":           len(bundle.Records),
		"started_at":             bundle.StartedAt,
		"ended_at":               bundle.EndedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}

	buf.Write(headerJSON)
	buf.WriteByte('\n')

	for _, rec := range bundle.Records {
		recJSON, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal record %d: %w", rec.SequenceNum, err)
		}
		buf.Write(recJSON)
		buf.WriteByte('\n')
	}

	return buf.Bytes(), nil
}

// ExportSARIF converts intercepted security violations and tripwire alerts into SARIF v2.1.0 format.
func ExportSARIF(bundle *SessionAuditBundle) ([]byte, error) {
	results := make([]map[string]any, 0)

	for _, rec := range bundle.Records {
		if rec.EventType == AuditEventTripwireAlert || rec.EventType == AuditEventEgressBlock {
			results = append(results, map[string]any{
				"ruleId": string(rec.EventType),
				"level":  "error",
				"message": map[string]string{
					"text": fmt.Sprintf("[%s] Violation in VM %s: %s", rec.EventType, rec.VMID, rec.PayloadJSON),
				},
			})
		}
	}

	sarifDoc := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":            "Aegisbox MicroVM Audit Gate",
						"version":         "1.0.0",
						"informationUri": "https://github.com/bonjoski/aegisbox",
					},
				},
				"results": results,
			},
		},
	}

	return json.MarshalIndent(sarifDoc, "", "  ")
}

// ExportOTLP formats audit records as OpenTelemetry (OTLP) log data for SIEM integration.
func ExportOTLP(bundle *SessionAuditBundle) ([]byte, error) {
	logs := make([]map[string]any, 0, len(bundle.Records))

	for _, rec := range bundle.Records {
		logs = append(logs, map[string]any{
			"timeUnixNano":   rec.TimestampUTC,
			"severityText":   string(rec.EventType),
			"body":           map[string]string{"stringValue": rec.PayloadJSON},
			"attributes": []map[string]any{
				{"key": "aegisbox.vm_id", "value": map[string]string{"stringValue": rec.VMID}},
				{"key": "aegisbox.seq", "value": map[string]uint64{"intValue": rec.SequenceNum}},
				{"key": "aegisbox.record_hash", "value": map[string]string{"stringValue": rec.RecordHashSHA256}},
			},
		})
	}

	otlpPayload := map[string]any{
		"resourceLogs": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []map[string]string{
						{"key": "service.name", "value": "aegisbox-audit"},
						{"key": "session.id", "value": bundle.SessionID},
					},
				},
				"scopeLogs": []map[string]any{
					{
						"logRecords": logs,
					},
				},
			},
		},
	}

	return json.MarshalIndent(otlpPayload, "", "  ")
}
