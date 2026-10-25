package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// GenesisHash is the root seed hash for audit chain initiation.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AuditSigner manages an append-only, tamper-evident cryptographic audit chain.
type AuditSigner struct {
	sessionID string
	pubKey    ed25519.PublicKey
	privKey   ed25519.PrivateKey
	prevHash  string
	sequence  uint64
	records   []AuditRecord
	startedAt time.Time
	mu        sync.Mutex
}

// NewAuditSigner initializes a signer with a fresh Ed25519 keypair for the session.
func NewAuditSigner(sessionID string) (*AuditSigner, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate audit signing keypair: %w", err)
	}

	return &AuditSigner{
		sessionID: sessionID,
		pubKey:    pub,
		privKey:   priv,
		prevHash:  GenesisHash,
		sequence:  0,
		records:   make([]AuditRecord, 0),
		startedAt: time.Now().UTC(),
	}, nil
}

// AppendEvent records a new event into the hash chain, computing SHA256 and Ed25519 signature.
func (s *AuditSigner) AppendEvent(eventType AuditEventType, vmID, payloadJSON string) (*AuditRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sequence++
	nowUTC := time.Now().UTC().Format(time.RFC3339Nano)

	// Compute canonical digest: seq | timestamp | prevHash | eventType | vmID | payload
	dataToHash := fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		s.sequence, nowUTC, s.prevHash, eventType, vmID, payloadJSON)

	h := sha256.Sum256([]byte(dataToHash))
	recordHash := hex.EncodeToString(h[:])

	// Sign the computed record hash
	sig := ed25519.Sign(s.privKey, []byte(recordHash))
	sigBase64 := base64.StdEncoding.EncodeToString(sig)

	record := AuditRecord{
		SequenceNum:          s.sequence,
		TimestampUTC:         nowUTC,
		PrevRecordHashSHA256: s.prevHash,
		EventType:            eventType,
		VMID:                 vmID,
		PayloadJSON:          payloadJSON,
		RecordHashSHA256:     recordHash,
		Signature:            sigBase64,
	}

	s.records = append(s.records, record)
	s.prevHash = recordHash

	return &record, nil
}

// ExportBundle seals and exports the complete session audit bundle.
func (s *AuditSigner) ExportBundle() *SessionAuditBundle {
	s.mu.Lock()
	defer s.mu.Unlock()

	recordsCopy := make([]AuditRecord, len(s.records))
	copy(recordsCopy, s.records)

	return &SessionAuditBundle{
		SessionID:         s.sessionID,
		StartedAt:         s.startedAt,
		EndedAt:           time.Now().UTC(),
		PublicKeyBase64:   base64.StdEncoding.EncodeToString(s.pubKey),
		GenesisHashSHA256: GenesisHash,
		FinalHashSHA256:   s.prevHash,
		Records:           recordsCopy,
	}
}

// VerifyAuditBundle validates the cryptographic integrity of an exported session audit bundle.
// Returns (true, 0, nil) if valid, or (false, tamperedSeq, error) on tampering.
func VerifyAuditBundle(bundle *SessionAuditBundle) (bool, uint64, error) {
	if bundle == nil {
		return false, 0, fmt.Errorf("nil audit bundle")
	}

	pubKeyBytes, err := base64.StdEncoding.DecodeString(bundle.PublicKeyBase64)
	if err != nil {
		return false, 0, fmt.Errorf("invalid public key base64: %w", err)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return false, 0, fmt.Errorf("invalid public key size: %d", len(pubKeyBytes))
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	expectedPrevHash := GenesisHash

	for i, record := range bundle.Records {
		expectedSeq := uint64(i + 1)
		if record.SequenceNum != expectedSeq {
			return false, record.SequenceNum, fmt.Errorf("sequence mismatch: expected %d, got %d", expectedSeq, record.SequenceNum)
		}

		if record.PrevRecordHashSHA256 != expectedPrevHash {
			return false, record.SequenceNum, fmt.Errorf("hash chain broken at sequence %d: expected prev hash %s, got %s",
				record.SequenceNum, expectedPrevHash, record.PrevRecordHashSHA256)
		}

		// Recompute hash
		dataToHash := fmt.Sprintf("%d|%s|%s|%s|%s|%s",
			record.SequenceNum, record.TimestampUTC, record.PrevRecordHashSHA256,
			record.EventType, record.VMID, record.PayloadJSON)

		h := sha256.Sum256([]byte(dataToHash))
		computedHash := hex.EncodeToString(h[:])

		if computedHash != record.RecordHashSHA256 {
			return false, record.SequenceNum, fmt.Errorf("tampered payload or hash at sequence %d: declared %s, computed %s",
				record.SequenceNum, record.RecordHashSHA256, computedHash)
		}

		// Verify signature
		sigBytes, err := base64.StdEncoding.DecodeString(record.Signature)
		if err != nil {
			return false, record.SequenceNum, fmt.Errorf("invalid signature base64 at sequence %d: %w", record.SequenceNum, err)
		}

		if !ed25519.Verify(pubKey, []byte(record.RecordHashSHA256), sigBytes) {
			return false, record.SequenceNum, fmt.Errorf("cryptographic signature verification failed at sequence %d", record.SequenceNum)
		}

		expectedPrevHash = record.RecordHashSHA256
	}

	if len(bundle.Records) > 0 && expectedPrevHash != bundle.FinalHashSHA256 {
		return false, uint64(len(bundle.Records)), fmt.Errorf("final hash mismatch: bundle declared %s, evaluated %s",
			bundle.FinalHashSHA256, expectedPrevHash)
	}

	return true, 0, nil
}
