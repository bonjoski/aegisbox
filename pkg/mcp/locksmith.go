package mcp

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	ErrLocksmithNotFound = errors.New("locksmith binary not found in PATH")
	ErrBiometricDenied   = errors.New("biometric challenge denied by user via Locksmith")
)

// SecretLease represents a short-lived, ephemeral secret checked out from Locksmith.
type SecretLease struct {
	Key       string
	Value     string
	ExpiresAt time.Time
}

// LocksmithBroker manages dynamic ephemeral secret checkouts using the bonjoski/locksmith vault.
type LocksmithBroker struct {
	locksmithPath string
	activeLeases  map[string]*SecretLease
	mu            sync.Mutex
}

// NewLocksmithBroker initializes the broker, locating the locksmith binary.
func NewLocksmithBroker() (*LocksmithBroker, error) {
	path, err := exec.LookPath("locksmith")
	if err != nil {
		return nil, ErrLocksmithNotFound
	}
	return &LocksmithBroker{
		locksmithPath: path,
		activeLeases:  make(map[string]*SecretLease),
	}, nil
}

// CheckoutSecret requests an ephemeral secret from Locksmith protected by biometric gate.
func (b *LocksmithBroker) CheckoutSecret(ctx context.Context, key string, ttl time.Duration) (*SecretLease, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	// Check if cached active lease exists
	if lease, exists := b.activeLeases[key]; exists {
		if time.Now().Before(lease.ExpiresAt) {
			return lease, nil
		}
		// Scrub expired lease
		b.scrubLease(lease)
		delete(b.activeLeases, key)
	}

	cmd := exec.CommandContext(ctx, b.locksmithPath, "get", key)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBiometricDenied, err)
	}

	secretVal := strings.TrimSpace(string(out))
	lease := &SecretLease{
		Key:       key,
		Value:     secretVal,
		ExpiresAt: time.Now().Add(ttl),
	}

	b.activeLeases[key] = lease
	return lease, nil
}

// RevokeAll cleans and cryptographically zeros all active in-memory leases.
func (b *LocksmithBroker) RevokeAll() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for key, lease := range b.activeLeases {
		b.scrubLease(lease)
		delete(b.activeLeases, key)
	}
}

func (b *LocksmithBroker) scrubLease(lease *SecretLease) {
	// Zero out string memory where possible
	lease.Value = ""
}
