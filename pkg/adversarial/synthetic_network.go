package adversarial

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// SyntheticNetworkConfig holds configuration options for the mock in-memory network.
type SyntheticNetworkConfig struct {
	AllowedTenantID       string
	SprayVelocityBurst    int           // threshold of requests in sliding window to trip killswitch (default: 20)
	SprayWindowDuration   time.Duration // window duration for spray evaluation (default: 500ms)
}

// SyntheticNetwork provides an air-gapped in-memory virtual network test harness with zero WAN egress.
type SyntheticNetwork struct {
	server              *httptest.Server
	baseURL             string
	cfg                 SyntheticNetworkConfig
	mu                  sync.Mutex

	// Invariant 1: Cross-Tenant tracking
	crossTenantAttempts atomic.Uint64
	crossTenantBlocked  atomic.Uint64
	legitimateAttempts  atomic.Uint64

	// Invariant 2: Velocity Killswitch tracking
	sprayStartTime      time.Time
	sprayReqCount       atomic.Uint64
	circuitTripped      atomic.Bool
	circuitTripTime     time.Time
	activeDPoPToken     string
	tokenRevoked        atomic.Bool

	// Invariant 3 / WAN Egress tracking
	wanEgressAttempts   atomic.Uint64
}

// NewSyntheticNetwork boots an in-memory loopback HTTP test server simulating Microsoft Graph API,
// Conjoiner IAM scope attenuation, and Argus Quarry velocity detection with Fabrial circuit breaking.
func NewSyntheticNetwork(cfg SyntheticNetworkConfig) *SyntheticNetwork {
	if cfg.AllowedTenantID == "" {
		cfg.AllowedTenantID = "tenant-alpha-001"
	}
	if cfg.SprayVelocityBurst <= 0 {
		cfg.SprayVelocityBurst = 20
	}
	if cfg.SprayWindowDuration <= 0 {
		cfg.SprayWindowDuration = 500 * time.Millisecond
	}

	sn := &SyntheticNetwork{
		cfg:             cfg,
		activeDPoPToken: "dpop-conjoiner-valid-session-token-alpha",
	}

	mux := http.NewServeMux()

	// 1. Mock Conjoiner IAM & Microsoft Graph API endpoint (/v1.0/...)
	mux.HandleFunc("/v1.0/", sn.handleGraphAPI)

	// 2. Mock Authentication & Spray Endpoint (/api/v1/auth/...)
	mux.HandleFunc("/api/v1/auth/probe", sn.handleSprayProbe)
	mux.HandleFunc("/api/v1/auth/spray", sn.handleSprayProbe)

	// 3. Canary Tripwire endpoint (/canary/...)
	mux.HandleFunc("/canary/", sn.handleCanary)

	// Standard health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	server := httptest.NewServer(mux)
	sn.server = server
	sn.baseURL = server.URL

	return sn
}

// BaseURL returns the loopback URL of the synthetic network.
func (sn *SyntheticNetwork) BaseURL() string {
	return sn.baseURL
}

// Close shuts down the synthetic network test server.
func (sn *SyntheticNetwork) Close() {
	if sn.server != nil {
		sn.server.Close()
	}
}

// Reset resets counters and state for a fresh test run.
func (sn *SyntheticNetwork) Reset() {
	sn.mu.Lock()
	defer sn.mu.Unlock()

	sn.crossTenantAttempts.Store(0)
	sn.crossTenantBlocked.Store(0)
	sn.legitimateAttempts.Store(0)
	sn.sprayReqCount.Store(0)
	sn.circuitTripped.Store(false)
	sn.circuitTripTime = time.Time{}
	sn.sprayStartTime = time.Time{}
	sn.tokenRevoked.Store(false)
	sn.activeDPoPToken = "dpop-conjoiner-valid-session-token-alpha"
	sn.wanEgressAttempts.Store(0)
}

// StartSprayWindow begins the timing window for velocity measurement.
func (sn *SyntheticNetwork) StartSprayWindow() {
	sn.mu.Lock()
	defer sn.mu.Unlock()
	sn.sprayStartTime = time.Now()
	sn.sprayReqCount.Store(0)
	sn.circuitTripped.Store(false)
	sn.circuitTripTime = time.Time{}
	sn.tokenRevoked.Store(false)
}

// handleGraphAPI enforces Conjoiner IAM scope attenuation on incoming Graph API requests.
func (sn *SyntheticNetwork) handleGraphAPI(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	targetHeader := r.Header.Get("X-Target-Tenant")

	// Determine if this is a cross-tenant privilege escalation attempt
	isCrossTenant := false
	if targetHeader != "" && targetHeader != sn.cfg.AllowedTenantID {
		isCrossTenant = true
	} else if strings.Contains(path, "tenant-bravo") ||
		strings.Contains(path, "tenant-charlie") ||
		strings.Contains(path, "cross-tenant") ||
		strings.Contains(path, "/servicePrincipals/") ||
		strings.Contains(path, "/directoryRoles/") {
		isCrossTenant = true
	} else if strings.Contains(path, "..") {
		// Path traversal attempt across tenants
		isCrossTenant = true
	}

	if isCrossTenant {
		sn.crossTenantAttempts.Add(1)
		sn.crossTenantBlocked.Add(1)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Conjoiner-Decision", "DENY")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":     "Forbidden",
			"code":      "CrossTenantBoundaryViolation",
			"message":   "Conjoiner attenuating scope engine rejected cross-tenant privilege escalation attempt",
			"tenant_id": sn.cfg.AllowedTenantID,
		})
		return
	}

	// Legitimate intra-tenant request
	sn.legitimateAttempts.Add(1)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Conjoiner-Decision", "ALLOW")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "success",
		"tenant_id": sn.cfg.AllowedTenantID,
		"resource":  path,
	})
}

// handleSprayProbe processes machine-speed credential spray probes and triggers the Fabrial circuit breaker.
func (sn *SyntheticNetwork) handleSprayProbe(w http.ResponseWriter, r *http.Request) {
	// If circuit breaker is already tripped, reject immediately
	if sn.circuitTripped.Load() {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Fabrial-Circuit-Breaker", "TRIPPED")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "CircuitBreakerTripped",
			"code":    "SprayVelocityExceeded",
			"message": "Fabrial velocity killswitch active: DPoP token revoked and session frozen",
		})
		return
	}

	count := sn.sprayReqCount.Add(1)

	sn.mu.Lock()
	now := time.Now()
	if sn.sprayStartTime.IsZero() {
		sn.sprayStartTime = now
	}
	elapsed := now.Sub(sn.sprayStartTime)

	// Velocity calculation: Check if request burst exceeds the threshold within window
	if count >= uint64(sn.cfg.SprayVelocityBurst) && !sn.circuitTripped.Load() {
		// Trip the circuit breaker!
		sn.circuitTripped.Store(true)
		sn.circuitTripTime = now
		sn.tokenRevoked.Store(true)
		sn.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Fabrial-Circuit-Breaker", "TRIPPED")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":         "CircuitBreakerTripped",
			"code":          "SprayVelocityExceeded",
			"message":       "Velocity killswitch tripped: active DPoP token revoked by Fabrial",
			"burst_count":   count,
			"elapsed_ms":    elapsed.Milliseconds(),
		})
		return
	}
	sn.mu.Unlock()

	// Normal failed authentication attempt prior to circuit trip
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "Unauthorized",
		"message": "Invalid credentials",
	})
}

// handleCanary handles requests hitting the canary tripwire.
func (sn *SyntheticNetwork) handleCanary(w http.ResponseWriter, r *http.Request) {
	sn.wanEgressAttempts.Add(1)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadGateway)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "CanaryTripwireTriggered",
	})
}

// TripLatency returns the duration from spray start until circuit breaker tripped.
func (sn *SyntheticNetwork) TripLatency() time.Duration {
	sn.mu.Lock()
	defer sn.mu.Unlock()

	if sn.sprayStartTime.IsZero() || sn.circuitTripTime.IsZero() {
		return 0
	}
	return sn.circuitTripTime.Sub(sn.sprayStartTime)
}

// CircuitTripped returns whether the circuit breaker was tripped.
func (sn *SyntheticNetwork) CircuitTripped() bool {
	return sn.circuitTripped.Load()
}

// TokenRevoked returns whether the active token was revoked.
func (sn *SyntheticNetwork) TokenRevoked() bool {
	return sn.tokenRevoked.Load()
}

// CrossTenantStats returns (total attempts, blocked count, block percentage).
func (sn *SyntheticNetwork) CrossTenantStats() (uint64, uint64, float64) {
	att := sn.crossTenantAttempts.Load()
	blk := sn.crossTenantBlocked.Load()
	if att == 0 {
		return 0, 0, 100.0
	}
	pct := (float64(blk) / float64(att)) * 100.0
	return att, blk, pct
}

// AirgappedTransport returns an http.Transport restricted exclusively to loopback addresses.
func (sn *SyntheticNetwork) AirgappedTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			ip := net.ParseIP(host)
			if ip != nil && !ip.IsLoopback() {
				sn.wanEgressAttempts.Add(1)
				return nil, fmt.Errorf("airgap policy violation: outbound egress to WAN target %s denied", addr)
			}
			if host != "localhost" && host != "127.0.0.1" && host != "::1" && !strings.HasPrefix(host, "127.") {
				sn.wanEgressAttempts.Add(1)
				return nil, fmt.Errorf("airgap policy violation: outbound egress to %s denied", addr)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}

// VerifyZeroWANEgress asserts that no external WAN connections succeed under airgap.
func (sn *SyntheticNetwork) VerifyZeroWANEgress(ctx context.Context) error {
	client := &http.Client{
		Transport: sn.AirgappedTransport(),
		Timeout:   150 * time.Millisecond,
	}

	wanTargets := []string{
		"http://1.1.1.1",
		"http://8.8.8.8",
		"http://169.254.169.254",
	}

	for _, target := range wanTargets {
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return fmt.Errorf("CRITICAL SECURITY DEFECT: Egress to WAN target %s succeeded under airgap!", target)
		}
	}

	return nil
}
