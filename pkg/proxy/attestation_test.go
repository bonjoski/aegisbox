package proxy

import (
	"os"
	"strings"
	"testing"
)

func TestAttestation_InspectCurrentProcess(t *testing.T) {
	pid := os.Getpid()
	id, err := InspectClient(pid)
	if err != nil {
		t.Fatalf("InspectClient failed for current process: %v", err)
	}

	if id.PID != pid {
		t.Errorf("expected PID %d, got %d", pid, id.PID)
	}
	if id.ExePath == "" {
		t.Errorf("expected non-empty ExePath")
	}
	if !strings.HasPrefix(id.ExeHash, "sha256:") {
		t.Errorf("expected ExeHash with sha256: prefix, got %q", id.ExeHash)
	}
}

func TestAttestation_HashFile(t *testing.T) {
	tempFile, err := os.CreateTemp("", "hash-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	content := "aegisbox client attestation payload"
	if _, err := tempFile.WriteString(content); err != nil {
		t.Fatalf("failed to write content: %v", err)
	}
	tempFile.Close()

	hash1, err := HashFile(tempFile.Name())
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}
	if !strings.HasPrefix(hash1, "sha256:") {
		t.Errorf("expected sha256 prefix, got %q", hash1)
	}

	// Hash again and verify deterministic output
	hash2, err := HashFile(tempFile.Name())
	if err != nil {
		t.Fatalf("second HashFile failed: %v", err)
	}
	if hash1 != hash2 {
		t.Errorf("expected identical hashes, got %q and %q", hash1, hash2)
	}
}

func TestAttestation_VerifyIdentityAndTamperRejection(t *testing.T) {
	pid := os.Getpid()
	id, err := InspectClient(pid)
	if err != nil {
		t.Fatalf("InspectClient failed: %v", err)
	}

	// 1. Valid hash matches
	if err := id.VerifyIdentity(id.ExeHash); err != nil {
		t.Errorf("expected valid hash verification to succeed: %v", err)
	}

	// 2. Tampered hash is rejected
	tamperedHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if err := id.VerifyIdentity(tamperedHash); err == nil {
		t.Errorf("expected tampered hash to be rejected")
	}

	// 3. AttestClient succeeds with valid hash
	attested, err := AttestClient(pid, id.ExeHash)
	if err != nil {
		t.Errorf("AttestClient failed: %v", err)
	}
	if attested.PID != pid {
		t.Errorf("PID mismatch: %d != %d", attested.PID, pid)
	}

	// 4. AttestClient fails with tampered hash
	if _, err := AttestClient(pid, tamperedHash); err == nil {
		t.Errorf("expected AttestClient with tampered hash to fail")
	}
}
