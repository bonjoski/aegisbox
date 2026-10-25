package identity

import (
	"crypto/rand"
	"fmt"
	"io"
)

// EntropyPool provides cryptographically secure random bytes for virtio-rng re-seeding.
type EntropyPool struct {
	reader io.Reader
}

// NewEntropyPool creates a pool using crypto/rand.
func NewEntropyPool() *EntropyPool {
	return &EntropyPool{reader: rand.Reader}
}

// GenerateEntropyBlock generates n bytes of cryptographic entropy.
func (e *EntropyPool) GenerateEntropyBlock(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("entropy block size must be positive, got %d", n)
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(e.reader, buf); err != nil {
		return nil, fmt.Errorf("failed to read entropy from system pool: %w", err)
	}

	return buf, nil
}

// ReseedSeed generates 256 bits (32 bytes) or 256 bytes of entropy specifically
// for virtio-rng re-seeding immediately upon microVM snapshot resume.
func (e *EntropyPool) ReseedSeed() ([]byte, error) {
	return e.GenerateEntropyBlock(256)
}
