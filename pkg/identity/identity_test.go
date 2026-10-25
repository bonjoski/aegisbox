package identity

import (
	"testing"
	"time"
)

func TestEntropyPool_ReseedSeed(t *testing.T) {
	pool := NewEntropyPool()
	seed, err := pool.ReseedSeed()
	if err != nil {
		t.Fatalf("failed to generate seed: %v", err)
	}

	if len(seed) != 256 {
		t.Fatalf("expected 256 bytes, got %d", len(seed))
	}

	// Verify not all zeros
	allZero := true
	for _, b := range seed {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Errorf("entropy block is completely zeroed")
	}
}

func TestSPIFFEBroker_IssueAndValidate(t *testing.T) {
	broker, err := NewSPIFFEBroker("test.aegisbox.local")
	if err != nil {
		t.Fatalf("failed to create broker: %v", err)
	}

	svid, err := broker.IssueWorkloadSVID("vm-01", "agent-runner", 5*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue svid: %v", err)
	}

	if svid.SPIFFEID != "spiffe://test.aegisbox.local/vm/vm-01/workload/agent-runner" {
		t.Errorf("unexpected SPIFFE ID: %s", svid.SPIFFEID)
	}

	valid, err := broker.ValidateSVID(svid)
	if err != nil || !valid {
		t.Errorf("expected valid SVID, got valid=%v, err=%v", valid, err)
	}

	// Test tamper detection
	svid.VMID = "vm-02" // Tamper payload
	tamperedValid, _ := broker.ValidateSVID(svid)
	if tamperedValid {
		t.Errorf("expected tampered SVID to be rejected")
	}
}
