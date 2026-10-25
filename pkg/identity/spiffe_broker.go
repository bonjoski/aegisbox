package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// SVID represents a signed workload SPIFFE Verifiable Identity Document.
type SVID struct {
	SPIFFEID  string    `json:"spiffe_id"`
	VMID      string    `json:"vm_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature string    `json:"signature"`
}

// SPIFFEBroker mints and validates local workload identities.
type SPIFFEBroker struct {
	trustDomain string
	pubKey      ed25519.PublicKey
	privKey     ed25519.PrivateKey
	mu          sync.RWMutex
}

// NewSPIFFEBroker initializes a local SPIFFE broker for the given trust domain.
func NewSPIFFEBroker(trustDomain string) (*SPIFFEBroker, error) {
	if trustDomain == "" {
		trustDomain = "aegisbox.local"
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SPIFFE signing key: %w", err)
	}

	return &SPIFFEBroker{
		trustDomain: trustDomain,
		pubKey:      pub,
		privKey:     priv,
	}, nil
}

// IssueWorkloadSVID mints an SVID for a microVM workload.
func (b *SPIFFEBroker) IssueWorkloadSVID(vmID, workloadID string, ttl time.Duration) (*SVID, error) {
	if vmID == "" || workloadID == "" {
		return nil, fmt.Errorf("vmID and workloadID must not be empty")
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	spiffeID := fmt.Sprintf("spiffe://%s/vm/%s/workload/%s", b.trustDomain, vmID, workloadID)
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	payload := fmt.Sprintf("%s|%s|%d|%d", spiffeID, vmID, now.Unix(), expiresAt.Unix())
	b.mu.RLock()
	sig := ed25519.Sign(b.privKey, []byte(payload))
	b.mu.RUnlock()

	return &SVID{
		SPIFFEID:  spiffeID,
		VMID:      vmID,
		IssuedAt:  now,
		ExpiresAt: expiresAt,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// ValidateSVID verifies an SVID's cryptographic signature and expiration.
func (b *SPIFFEBroker) ValidateSVID(svid *SVID) (bool, error) {
	if svid == nil {
		return false, fmt.Errorf("svid cannot be nil")
	}

	if time.Now().UTC().After(svid.ExpiresAt) {
		return false, fmt.Errorf("svid expired at %s", svid.ExpiresAt)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(svid.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid base64 signature: %w", err)
	}

	payload := fmt.Sprintf("%s|%s|%d|%d", svid.SPIFFEID, svid.VMID, svid.IssuedAt.Unix(), svid.ExpiresAt.Unix())
	b.mu.RLock()
	valid := ed25519.Verify(b.pubKey, []byte(payload), sigBytes)
	b.mu.RUnlock()

	return valid, nil
}
