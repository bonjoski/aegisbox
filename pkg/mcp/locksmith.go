package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bonjoski/aegisbox/pkg/policy"
)

const (
	// LocksmithProtocolVersion is the ETX UDS wire protocol version.
	LocksmithProtocolVersion = "1.0"

	// ActionRedeemOpaqueLease exchanges an opaque lease handle for ephemeral secret bytes over UDS.
	ActionRedeemOpaqueLease = "redeem_opaque_lease"

	// ActionSignDSSE signs a BLPR-v1 DSSE PAE digest using Locksmith's amortized session Ed25519 key.
	ActionSignDSSE = "sign_dsse"

	// ActionRevokeLease notifies Locksmith that an ephemeral lease is no longer needed.
	ActionRevokeLease = "revoke_lease"

	defaultLocksmithDialTimeout = 2 * time.Second
	maxLocksmithResponseBytes   = 1 << 20 // 1 MiB
)

var (
	ErrLocksmithNotFound    = errors.New("locksmith socket not found")
	ErrLocksmithUnavailable = errors.New("locksmith UDS daemon unavailable")
	ErrBiometricDenied      = errors.New("biometric challenge denied or required via Locksmith")
	ErrOpaqueLeaseDenied    = errors.New("opaque secret lease denied by Locksmith")

	validEnvVarRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	exeHashOnce sync.Once
	exeHashHex  string
)

// SecretLease represents a short-lived, ephemeral secret redeemed from Locksmith over UDS.
// Secret material is stored strictly in a mutable []byte so it can be deterministically
// zeroed via clear(l.Value) without leaving immutable Go string copies on the heap.
type SecretLease struct {
	LeaseID   string
	Key       string // Target environment variable name (e.g. "STRIPE_API_KEY")
	Value     []byte // Zeroizable secret bytes; cleared via clear(Value) on Scrub/RevokeAll
	ExpiresAt time.Time
	mu        sync.Mutex
}

// Bytes returns the underlying secret byte slice (nil after Scrub).
func (l *SecretLease) Bytes() []byte {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Value
}

// Scrub deterministically overwrites every byte of the secret slice with zeroes and drops the reference.
func (l *SecretLease) Scrub() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.Value) > 0 {
		clear(l.Value)
		runtime.KeepAlive(l.Value)
	}
	l.Value = nil
}

// ResolveLocksmithSocket determines the local Locksmith Unix Domain Socket path.
// Checks LOCKSMITH_SOCKET, LOCKSMITH_SOCK, and defaults to ~/.locksmith/locksmith.sock.
func ResolveLocksmithSocket() string {
	if sock := strings.TrimSpace(os.Getenv("LOCKSMITH_SOCKET")); sock != "" {
		return sock
	}
	if sock := strings.TrimSpace(os.Getenv("LOCKSMITH_SOCK")); sock != "" {
		return sock
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".locksmith", "locksmith.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("locksmith-%d.sock", os.Getuid()))
}

// LocksmithBroker communicates directly with the local Locksmith UDS daemon
// for zero-subprocess opaque lease redemption and amortized BLPR-v1 DSSE signing.
type LocksmithBroker struct {
	socketPath   string
	dialTimeout  time.Duration
	activeLeases map[string]*SecretLease
	mu           sync.Mutex
}

// NewLocksmithBroker initializes a UDS-backed broker targeting LOCKSMITH_SOCKET (~/.locksmith/locksmith.sock).
func NewLocksmithBroker() (*LocksmithBroker, error) {
	sock := ResolveLocksmithSocket()
	if sock == "" {
		return nil, ErrLocksmithNotFound
	}
	return NewLocksmithBrokerWithSocket(sock), nil
}

// NewLocksmithBrokerWithSocket initializes a UDS-backed broker targeting an explicit socket path.
func NewLocksmithBrokerWithSocket(socketPath string) *LocksmithBroker {
	if strings.TrimSpace(socketPath) == "" {
		socketPath = ResolveLocksmithSocket()
	}
	return &LocksmithBroker{
		socketPath:   socketPath,
		dialTimeout:  defaultLocksmithDialTimeout,
		activeLeases: make(map[string]*SecretLease),
	}
}

// SocketPath returns the configured Locksmith Unix Domain Socket path.
func (b *LocksmithBroker) SocketPath() string {
	if b == nil {
		return ""
	}
	return b.socketPath
}

type redeemOpaqueLeaseRequest struct {
	Version          string `json:"version"`
	Action           string `json:"action"`
	LeaseID          string `json:"lease_id"`
	SessionID        string `json:"session_id,omitempty"`
	ClientPID        int    `json:"client_pid"`
	ProcessStartTime int64  `json:"process_start_time"`
	ClientBinaryHash string `json:"client_binary_hash,omitempty"`
}

type redeemOpaqueLeaseResponse struct {
	Status         string    `json:"status"`
	LeaseID        string    `json:"lease_id,omitempty"`
	EnvVar         string    `json:"env_var,omitempty"`
	TargetEnvVar   string    `json:"target_env_var,omitempty"`
	SecretName     string    `json:"secret_name,omitempty"`
	SecretValue    []byte    `json:"secret_value,omitempty"`
	SecretB64      string    `json:"secret_b64,omitempty"`
	SecretValueB64 string    `json:"secret_value_b64,omitempty"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	Error          string    `json:"error,omitempty"`
}

type signDSSERequest struct {
	Version          string `json:"version"`
	Action           string `json:"action"`
	SessionID        string `json:"session_id"`
	PAEB64           string `json:"pae_b64"`
	ClientPID        int    `json:"client_pid"`
	ProcessStartTime int64  `json:"process_start_time"`
	ClientBinaryHash string `json:"client_binary_hash,omitempty"`
}

type signDSSEResponse struct {
	Status   string `json:"status"`
	KeyID    string `json:"keyid,omitempty"`
	KeyIDAlt string `json:"key_id,omitempty"`
	Sig      string `json:"sig,omitempty"`
	SigB64   string `json:"sig_b64,omitempty"`
	Error    string `json:"error,omitempty"`
}

// RedeemOpaqueLease exchanges an opaque lease_id for zeroizable secret bytes over the Locksmith UDS.
// No subprocesses are spawned and no secret strings are retained on the heap.
func (b *LocksmithBroker) RedeemOpaqueLease(ctx context.Context, leaseID, sessionID string) (*SecretLease, error) {
	if b == nil {
		return nil, ErrLocksmithUnavailable
	}
	leaseID = strings.TrimSpace(leaseID)
	if leaseID == "" || strings.ContainsAny(leaseID, "\x00\r\n") {
		return nil, fmt.Errorf("%w: invalid lease_id", ErrOpaqueLeaseDenied)
	}

	req := redeemOpaqueLeaseRequest{
		Version:          LocksmithProtocolVersion,
		Action:           ActionRedeemOpaqueLease,
		LeaseID:          leaseID,
		SessionID:        strings.TrimSpace(sessionID),
		ClientPID:        os.Getpid(),
		ProcessStartTime: currentProcessStartTime(),
		ClientBinaryHash: currentClientBinaryHash(),
	}

	rawResp, err := b.roundTripUDS(ctx, req)
	if err != nil {
		return nil, err
	}
	defer func() {
		clear(rawResp)
		runtime.KeepAlive(rawResp)
	}()

	var resp redeemOpaqueLeaseResponse
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return nil, fmt.Errorf("%w: invalid daemon response: %v", ErrOpaqueLeaseDenied, err)
	}

	status := strings.ToUpper(strings.TrimSpace(resp.Status))
	if status == "CHALLENGE_REQUIRED" {
		clear(resp.SecretValue)
		return nil, fmt.Errorf("%w: %s", ErrBiometricDenied, strings.TrimSpace(resp.Error))
	}
	if status != "GRANTED" && status != "OK" {
		clear(resp.SecretValue)
		msg := strings.TrimSpace(resp.Error)
		if msg == "" {
			msg = status
		}
		if msg == "" {
			msg = "lease rejected"
		}
		return nil, fmt.Errorf("%w: %s", ErrOpaqueLeaseDenied, msg)
	}

	secretBytes := resp.SecretValue
	if len(secretBytes) == 0 {
		b64Payload := resp.SecretB64
		if b64Payload == "" {
			b64Payload = resp.SecretValueB64
		}
		if b64Payload != "" {
			decoded, decErr := base64.StdEncoding.DecodeString(b64Payload)
			if decErr != nil {
				return nil, fmt.Errorf("%w: invalid base64 secret payload", ErrOpaqueLeaseDenied)
			}
			secretBytes = decoded
		}
	}
	if len(secretBytes) == 0 {
		return nil, fmt.Errorf("%w: empty secret payload returned", ErrOpaqueLeaseDenied)
	}

	envVar := strings.TrimSpace(resp.EnvVar)
	if envVar == "" {
		envVar = strings.TrimSpace(resp.TargetEnvVar)
	}
	if envVar == "" {
		envVar = strings.TrimSpace(resp.SecretName)
	}
	if envVar == "" || !validEnvVarRe.MatchString(envVar) || policy.IsDangerousEnvVar(envVar) {
		clear(secretBytes)
		runtime.KeepAlive(secretBytes)
		return nil, fmt.Errorf("%w: unsafe or missing target env_var %q", ErrOpaqueLeaseDenied, envVar)
	}

	expiresAt := resp.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(5 * time.Minute)
	}

	resolvedLeaseID := strings.TrimSpace(resp.LeaseID)
	if resolvedLeaseID == "" {
		resolvedLeaseID = leaseID
	}

	lease := &SecretLease{
		LeaseID:   resolvedLeaseID,
		Key:       envVar,
		Value:     secretBytes,
		ExpiresAt: expiresAt,
	}

	b.mu.Lock()
	if prev, exists := b.activeLeases[leaseID]; exists {
		prev.Scrub()
	}
	b.activeLeases[leaseID] = lease
	b.mu.Unlock()

	return lease, nil
}

// CheckoutSecret provides backward compatibility for callers expecting CheckoutSecret,
// routing directly over the Locksmith UDS via RedeemOpaqueLease (zero subprocesses).
func (b *LocksmithBroker) CheckoutSecret(ctx context.Context, key string, ttl time.Duration) (*SecretLease, error) {
	if b == nil {
		return nil, ErrLocksmithUnavailable
	}

	b.mu.Lock()
	if lease, exists := b.activeLeases[key]; exists {
		if time.Now().Before(lease.ExpiresAt) && len(lease.Bytes()) > 0 {
			b.mu.Unlock()
			return lease, nil
		}
		lease.Scrub()
		delete(b.activeLeases, key)
	}
	b.mu.Unlock()

	lease, err := b.RedeemOpaqueLease(ctx, key, os.Getenv("FABRIAL_SESSION_ID"))
	if err != nil {
		return nil, err
	}
	if ttl > 0 && lease.ExpiresAt.IsZero() {
		lease.ExpiresAt = time.Now().Add(ttl)
	}
	return lease, nil
}

// SignDSSE requests an amortized Ed25519 signature over a BLPR-v1 DSSE PAE digest via Locksmith UDS.
func (b *LocksmithBroker) SignDSSE(ctx context.Context, sessionID string, pae []byte) (string, []byte, error) {
	if b == nil {
		return "", nil, ErrLocksmithUnavailable
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return "", nil, errors.New("locksmith sign_dsse: session_id is required")
	}
	if len(pae) == 0 {
		return "", nil, errors.New("locksmith sign_dsse: pae payload is empty")
	}

	req := signDSSERequest{
		Version:          LocksmithProtocolVersion,
		Action:           ActionSignDSSE,
		SessionID:        sessionID,
		PAEB64:           base64.StdEncoding.EncodeToString(pae),
		ClientPID:        os.Getpid(),
		ProcessStartTime: currentProcessStartTime(),
		ClientBinaryHash: currentClientBinaryHash(),
	}

	rawResp, err := b.roundTripUDS(ctx, req)
	if err != nil {
		return "", nil, err
	}

	var resp signDSSEResponse
	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return "", nil, fmt.Errorf("locksmith sign_dsse: invalid daemon response: %w", err)
	}

	status := strings.ToUpper(strings.TrimSpace(resp.Status))
	if status == "CHALLENGE_REQUIRED" {
		return "", nil, fmt.Errorf("%w: %s", ErrBiometricDenied, strings.TrimSpace(resp.Error))
	}
	if resp.Error != "" || (status != "" && status != "OK" && status != "GRANTED") {
		msg := strings.TrimSpace(resp.Error)
		if msg == "" {
			msg = status
		}
		return "", nil, fmt.Errorf("locksmith sign_dsse denied: %s", msg)
	}

	keyID := strings.TrimSpace(resp.KeyID)
	if keyID == "" {
		keyID = strings.TrimSpace(resp.KeyIDAlt)
	}
	sigB64 := strings.TrimSpace(resp.Sig)
	if sigB64 == "" {
		sigB64 = strings.TrimSpace(resp.SigB64)
	}
	if keyID == "" || sigB64 == "" {
		return "", nil, errors.New("locksmith sign_dsse: missing keyid or signature in response")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sigBytes) == 0 {
		return "", nil, errors.New("locksmith sign_dsse: invalid base64 signature")
	}

	return keyID, sigBytes, nil
}

// RevokeAll deterministically zeroes all active in-memory secret byte slices and clears the lease map.
func (b *LocksmithBroker) RevokeAll() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	for key, lease := range b.activeLeases {
		lease.Scrub()
		delete(b.activeLeases, key)
	}
}

func (b *LocksmithBroker) roundTripUDS(ctx context.Context, payload interface{}) ([]byte, error) {
	timeout := b.dialTimeout
	if timeout <= 0 {
		timeout = defaultLocksmithDialTimeout
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", b.socketPath)
	if err != nil {
		return nil, fmt.Errorf("%w (%s): %v", ErrLocksmithUnavailable, b.socketPath, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	}

	encBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("locksmith uds encode: %w", err)
	}
	encBytes = append(encBytes, '\n')
	if _, err := conn.Write(encBytes); err != nil {
		return nil, fmt.Errorf("%w: write failed: %v", ErrLocksmithUnavailable, err)
	}

	raw, err := io.ReadAll(io.LimitReader(conn, maxLocksmithResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: read failed: %v", ErrLocksmithUnavailable, err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: empty response from daemon", ErrLocksmithUnavailable)
	}
	return raw, nil
}

func currentProcessStartTime() int64 {
	ts, err := getProcessStartTime(os.Getpid())
	if err != nil || ts <= 0 {
		return time.Now().UnixNano()
	}
	return ts
}

func currentClientBinaryHash() string {
	exeHashOnce.Do(func() {
		exe, err := os.Executable()
		if err != nil || exe == "" {
			return
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
			exe = resolved
		}
		f, err := os.Open(exe)
		if err != nil {
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return
		}
		exeHashHex = hex.EncodeToString(h.Sum(nil))
	})
	return exeHashHex
}
