package ipc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc/metadata"
)

var (
	// ErrInvalidToken is returned when an IPC caller presents an unrecognized or expired session token.
	ErrInvalidToken = errors.New("invalid or expired IPC session token")
	// ErrRateLimitExceeded is returned when IPC requests exceed safe rate thresholds.
	ErrRateLimitExceeded = errors.New("IPC request rate limit exceeded")
)

// AdminTokenFilePath returns the mode-0600 host-operator admin capability file path paired with socketPath.
func AdminTokenFilePath(socketPath string) string {
	return filepath.Join(filepath.Dir(socketPath), "admin.token")
}

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

// TokenStore manages active authenticated sessions, enforces constant-time validation,
// and separates privileged host-operator admin capability from unprivileged workload tokens.
type TokenStore struct {
	mu          sync.RWMutex
	sessions    map[string]*SessionInfo
	ttl         time.Duration
	adminSecret string
	adminFile   string
}

// NewTokenStore initializes a session token store with a specified session time-to-live.
func NewTokenStore(ttl time.Duration) *TokenStore {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	adminBytes := make([]byte, 32)
	if _, err := rand.Read(adminBytes); err != nil {
		panic(fmt.Sprintf("ipc: failed to initialize CSPRNG admin capability secret: %v", err))
	}
	return &TokenStore{
		sessions:    make(map[string]*SessionInfo),
		ttl:         ttl,
		adminSecret: hex.EncodeToString(adminBytes),
	}
}

// WriteAdminSecretFile persists the privileged operator admin token next to the Unix socket with 0600 permissions.
// Sandboxed workloads cannot read ~/.aegisbox/admin.token, preventing workload self-approval over IPC.
func (s *TokenStore) WriteAdminSecretFile(socketPath string) error {
	if socketPath == "" {
		return nil
	}
	adminPath := AdminTokenFilePath(socketPath)
	if err := os.MkdirAll(filepath.Dir(adminPath), 0700); err != nil {
		return fmt.Errorf("failed creating admin token directory: %w", err)
	}
	s.mu.RLock()
	secret := s.adminSecret
	s.mu.RUnlock()

	if err := os.WriteFile(adminPath, []byte(secret), 0600); err != nil {
		return fmt.Errorf("failed writing admin capability file %s: %w", adminPath, err)
	}
	s.mu.Lock()
	s.adminFile = adminPath
	s.mu.Unlock()
	return nil
}

// CleanupAdminSecretFile removes the persisted admin token file on daemon shutdown.
func (s *TokenStore) CleanupAdminSecretFile() error {
	s.mu.Lock()
	adminPath := s.adminFile
	s.adminFile = ""
	s.mu.Unlock()
	if adminPath == "" {
		return nil
	}
	if err := os.Remove(adminPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed removing admin capability file %s: %w", adminPath, err)
	}
	return nil
}

// ValidateAdminCapability verifies constant-time possession of the privileged operator admin secret.
func (s *TokenStore) ValidateAdminCapability(candidate string) bool {
	if len(candidate) != 64 {
		return false
	}
	s.mu.RLock()
	secret := s.adminSecret
	s.mu.RUnlock()
	return len(secret) == 64 && subtle.ConstantTimeCompare([]byte(secret), []byte(candidate)) == 1
}

// ValidateAdminContext verifies that the incoming gRPC request carries BOTH a valid session token
// AND the privileged host-operator admin capability header.
func (s *TokenStore) ValidateAdminContext(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	sessionVals := md.Get("x-aegisbox-session-token")
	if len(sessionVals) == 0 || !s.ValidateToken(sessionVals[0]) {
		return false
	}
	adminVals := md.Get("x-aegisbox-admin-token")
	if len(adminVals) == 0 {
		return false
	}
	return s.ValidateAdminCapability(adminVals[0])
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

	for storedToken, session := range s.sessions {
		if subtle.ConstantTimeCompare([]byte(storedToken), []byte(token)) == 1 {
			matchedSession = session
			break
		}
	}

	if matchedSession == nil {
		return false
	}

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
