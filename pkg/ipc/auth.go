package ipc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrInvalidToken is returned when an IPC caller presents an unrecognized or expired session token.
	ErrInvalidToken = errors.New("invalid or expired IPC session token")
	// ErrRateLimitExceeded is returned when IPC requests exceed safe rate thresholds.
	ErrRateLimitExceeded = errors.New("IPC request rate limit exceeded")
)

// SessionInfo holds metadata about an authenticated client session.
type SessionInfo struct {
	Token          string
	ClientPID      uint32
	ClientVersion  string
	ClientPlatform string
	CreatedAt      time.Time
	LastActivity   time.Time
	RequestCount   uint64
}

// TokenStore manages active authenticated sessions and enforces constant-time validation.
type TokenStore struct {
	mu       sync.RWMutex
	sessions map[string]*SessionInfo
	ttl      time.Duration
}

// NewTokenStore initializes a session token store with a specified session time-to-live.
func NewTokenStore(ttl time.Duration) *TokenStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &TokenStore{
		sessions: make(map[string]*SessionInfo),
		ttl:      ttl,
	}
}

// IssueToken generates a cryptographically random 256-bit session token and records the session.
func (s *TokenStore) IssueToken(clientPID uint32, version, platform string) (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure session entropy: %w", err)
	}
	token := hex.EncodeToString(bytes)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.sessions[token] = &SessionInfo{
		Token:          token,
		ClientPID:      clientPID,
		ClientVersion:  version,
		ClientPlatform: platform,
		CreatedAt:      now,
		LastActivity:   now,
	}

	return token, nil
}

// ValidateToken checks if a token is valid, active, and unexpired using constant-time comparison.
func (s *TokenStore) ValidateToken(token string) bool {
	if len(token) != 64 {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	var matchedSession *SessionInfo

	// Scan sessions using constant-time comparison to prevent timing leaks
	for storedToken, session := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(storedToken), []byte(token)) == 1 {
			matchedSession = session
			break
		}
	}

	if matchedSession == nil {
		return false
	}

	// Check expiration
	if now.Sub(matchedSession.LastActivity) > s.ttl {
		delete(s.sessions, matchedSession.Token)
		return false
	}

	matchedSession.LastActivity = now
	matchedSession.RequestCount++
	return true
}

// RevokeToken removes a token upon client disconnection.
func (s *TokenStore) RevokeToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}

// ActiveSessionCount returns the count of live sessions.
func (s *TokenStore) ActiveSessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
