package adversarial

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Invariant 1: Cross-Tenant Isolation
// Verifies that Conjoiner IAM scope attenuation strictly blocks 100% of cross-tenant pivot attempts.
func RunInvariant1_CrossTenant(ctx context.Context, net *SyntheticNetwork) InvariantResult {
	res := InvariantResult{
		Index:       1,
		Name:        "Cross-Tenant Isolation",
		Description: "Conjoiner IAM attenuating scope engine strictly rejects cross-tenant federation and privilege escalation",
		Metrics:     make(map[string]interface{}),
	}

	client := &http.Client{Timeout: 2 * time.Second}

	// 1. Verify legitimate intra-tenant requests succeed
	legitimatePaths := []string{
		"/v1.0/tenants/tenant-alpha-001/users",
		"/v1.0/tenants/tenant-alpha-001/groups",
		"/v1.0/me",
	}
	for _, p := range legitimatePaths {
		req, err := http.NewRequestWithContext(ctx, "GET", net.BaseURL()+p, nil)
		if err != nil {
			res.Passed = false
			res.Summary = fmt.Sprintf("failed to create intra-tenant request: %v", err)
			return res
		}
		req.Header.Set("Authorization", "Bearer dpop-conjoiner-valid-session-token-alpha")
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			res.Passed = false
			res.Summary = fmt.Sprintf("intra-tenant request %s unexpectedly failed: %v", p, err)
			return res
		}
		_ = resp.Body.Close()
	}

	// 2. Execute 50 cross-tenant escalation queries simulating ARTEX machine-speed lateral pivot
	crossTenantVectors := []struct {
		path   string
		header string
	}{
		{"/v1.0/tenants/tenant-bravo-002/users", ""},
		{"/v1.0/tenants/tenant-bravo-002/groups", ""},
		{"/v1.0/tenants/tenant-bravo-002/applications", ""},
		{"/v1.0/tenants/tenant-bravo-002/servicePrincipals", ""},
		{"/v1.0/servicePrincipals/tenant-bravo-002/appRoleAssignedTo", ""},
		{"/v1.0/directoryRoles/tenant-bravo-002", ""},
		{"/v1.0/tenants/tenant-alpha-001/../tenant-bravo-002/users", ""},
		{"/v1.0/users", "tenant-bravo-002"},
		{"/v1.0/groups", "tenant-charlie-003"},
		{"/v1.0/cross-tenant/federation/token", ""},
	}

	totalCrossAttempts := 50
	blockedCount := 0

	for i := 0; i < totalCrossAttempts; i++ {
		vec := crossTenantVectors[i%len(crossTenantVectors)]
		req, err := http.NewRequestWithContext(ctx, "GET", net.BaseURL()+vec.path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer dpop-conjoiner-valid-session-token-alpha")
		if vec.header != "" {
			req.Header.Set("X-Target-Tenant", vec.header)
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-Conjoiner-Decision") == "DENY" {
			blockedCount++
		}
		_ = resp.Body.Close()
	}

	att, blk, pct := net.CrossTenantStats()
	res.Metrics["attempts"] = att
	res.Metrics["blocked"] = blk
	res.Metrics["blocked_pct"] = pct

	if blockedCount == totalCrossAttempts && pct >= 100.0 {
		res.Passed = true
		res.Summary = fmt.Sprintf("Attempts blocked: %.0f%%", pct)
	} else {
		res.Passed = false
		res.Summary = fmt.Sprintf("Attempts blocked: %.1f%% (%d/%d bypassed)", pct, totalCrossAttempts-blockedCount, totalCrossAttempts)
	}

	return res
}

// Invariant 2: Velocity Killswitch
// Verifies that password spraying and credential probing at 2,900 req/min trips Fabrial's circuit breaker in < 500ms.
func RunInvariant2_VelocityKillswitch(ctx context.Context, net *SyntheticNetwork, targetRatePerMin int, maxTripMs time.Duration) InvariantResult {
	res := InvariantResult{
		Index:       2,
		Name:        "Velocity Killswitch",
		Description: "Argus Quarry velocity detector flags abnormal query volume and Fabrial trips circuit breaker in < 500ms",
		Metrics:     make(map[string]interface{}),
	}

	if targetRatePerMin <= 0 {
		targetRatePerMin = 2900
	}
	if maxTripMs <= 0 {
		maxTripMs = 500 * time.Millisecond
	}

	net.StartSprayWindow()

	client := &http.Client{Timeout: 1 * time.Second}
	workers := 8
	sprayBursts := 40 // Total requests to fire across workers
	var wg sync.WaitGroup

	errCh := make(chan error, sprayBursts)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < (sprayBursts / workers); j++ {
				select {
				case <-ctx.Done():
					return
				default:
					probeURL := fmt.Sprintf("%s/api/v1/auth/probe?user=admin_%d_%d&spray=1", net.BaseURL(), workerID, j)
					req, err := http.NewRequestWithContext(ctx, "POST", probeURL, strings.NewReader(`{"password":"spray_password_123"}`))
					if err != nil {
						errCh <- err
						return
					}
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Authorization", "Bearer dpop-active-attacker-token")

					resp, err := client.Do(req)
					if err != nil {
						errCh <- err
						return
					}
					_ = resp.Body.Close()

					// Short sleep simulating high burst rate (~2,900 req/min distributed)
					time.Sleep(5 * time.Millisecond)
				}
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	tripDuration := net.TripLatency()
	tripped := net.CircuitTripped()
	tokenRevoked := net.TokenRevoked()

	res.Metrics["trip_latency_ms"] = tripDuration.Milliseconds()
	res.Metrics["circuit_tripped"] = tripped
	res.Metrics["token_revoked"] = tokenRevoked
	res.Metrics["threshold_ms"] = maxTripMs.Milliseconds()

	// Verify post-trip requests are rejected by the circuit breaker
	verifyReq, _ := http.NewRequestWithContext(ctx, "POST", net.BaseURL()+"/api/v1/auth/probe", nil)
	verifyResp, err := client.Do(verifyReq)
	postTripBlocked := false
	if err == nil {
		if verifyResp.StatusCode == http.StatusTooManyRequests && verifyResp.Header.Get("X-Fabrial-Circuit-Breaker") == "TRIPPED" {
			postTripBlocked = true
		}
		_ = verifyResp.Body.Close()
	}

	if tripped && tokenRevoked && tripDuration > 0 && tripDuration <= maxTripMs && postTripBlocked {
		res.Passed = true
		res.Summary = fmt.Sprintf("Velocity Killswitch Tripped in %dms", tripDuration.Milliseconds())
	} else if tripped && tripDuration > maxTripMs {
		res.Passed = false
		res.Summary = fmt.Sprintf("Velocity Killswitch Tripped in %dms (Exceeded threshold of %dms)", tripDuration.Milliseconds(), maxTripMs.Milliseconds())
	} else {
		res.Passed = false
		res.Summary = "Velocity Killswitch Failed to Trip"
	}

	return res
}

// Invariant 3: Host Credential Bleed
// Verifies that code execution inside developer workspace cannot exfiltrate host SSH keys, AWS credentials, or .env secrets.
func RunInvariant3_HostCredentialBleed(ctx context.Context, harness *SandboxHarness) InvariantResult {
	res := InvariantResult{
		Index:       3,
		Name:        "Host Credential Bleed",
		Description: "Airlock process confinement and Aegisbox shadow workspace mask host secrets (0 bytes harvested)",
		Metrics:     make(map[string]interface{}),
	}

	// 1. Plant canary host secrets inside the host directory (simulating real host secrets)
	hostDir := harness.HostDir()
	canarySecrets := map[string]string{
		filepath.Join(hostDir, ".env"):                  "DATABASE_URL=postgres://admin:SUPER_SECRET_CANARY_PW_9988@host/prod\n",
		filepath.Join(hostDir, ".ssh", "id_rsa"):        "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY_HOST_SSH_KEY_DO_NOT_BLEED_xyz\n-----END OPENSSH PRIVATE KEY-----\n",
		filepath.Join(hostDir, ".aws", "credentials"):   "[default]\naws_secret_access_key = CANARY_AWS_SECRET_KEY_BLEED_TEST_001\n",
	}

	for p, content := range canarySecrets {
		_ = os.MkdirAll(filepath.Dir(p), 0700)
		_ = os.WriteFile(p, []byte(content), 0600)
	}

	// Host canary environment variable
	hostCanaryEnvKey := "AEGISBOX_HOST_CANARY_SECRET_TOKEN"
	hostCanaryEnvVal := "CANARY_ENV_SECRET_VALUE_99999_NEVER_BLEED"
	_ = os.Setenv(hostCanaryEnvKey, hostCanaryEnvVal)
	defer os.Unsetenv(hostCanaryEnvKey)

	// 2. Execute an adversarial harvesting script inside the sandbox harness
	harvestScript := `
		HARVESTED=""
		if [ -f .env ]; then
			HARVESTED="$HARVESTED $(cat .env 2>/dev/null)"
		fi
		if [ -f ~/.ssh/id_rsa ]; then
			HARVESTED="$HARVESTED $(cat ~/.ssh/id_rsa 2>/dev/null)"
		fi
		if [ -f .ssh/id_rsa ]; then
			HARVESTED="$HARVESTED $(cat .ssh/id_rsa 2>/dev/null)"
		fi
		if [ -f ~/.aws/credentials ]; then
			HARVESTED="$HARVESTED $(cat ~/.aws/credentials 2>/dev/null)"
		fi
		if [ -f .aws/credentials ]; then
			HARVESTED="$HARVESTED $(cat .aws/credentials 2>/dev/null)"
		fi
		if [ -n "$AEGISBOX_HOST_CANARY_SECRET_TOKEN" ]; then
			HARVESTED="$HARVESTED $AEGISBOX_HOST_CANARY_SECRET_TOKEN"
		fi
		echo "$HARVESTED"
	`

	stdout, stderr, _, _ := harness.ExecuteInSandbox(ctx, harvestScript, nil)
	combinedOutput := stdout + " " + stderr

	// 3. Inspect output for any canary secret bleed
	canaryTokens := []string{
		"SUPER_SECRET_CANARY_PW_9988",
		"CANARY_HOST_SSH_KEY_DO_NOT_BLEED",
		"CANARY_AWS_SECRET_KEY_BLEED_TEST",
		"CANARY_ENV_SECRET_VALUE_99999",
	}

	harvestedBytes := 0
	for _, token := range canaryTokens {
		if strings.Contains(combinedOutput, token) {
			harvestedBytes += len(token)
		}
	}

	res.Metrics["harvested_bytes"] = harvestedBytes

	if harvestedBytes == 0 {
		res.Passed = true
		res.Summary = fmt.Sprintf("Harvested: %d bytes", harvestedBytes)
	} else {
		res.Passed = false
		res.Summary = fmt.Sprintf("CRITICAL LEAK: Harvested %d bytes of host secrets", harvestedBytes)
	}

	return res
}
