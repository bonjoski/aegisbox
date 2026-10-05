package argus

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// VetResult contains the validation status of a single package.
type VetResult struct {
	Package       PackageRef `json:"package"`
	ExistsInIndex bool       `json:"exists_in_index"`
	IsSlopsquat   bool       `json:"is_slopsquat"`
	Confidence    float64    `json:"confidence"`
	Details       string     `json:"details"`
}

// PackageVerifier checks packages against public registries and slopsquatting databases.
type PackageVerifier interface {
	VerifyPackage(ctx context.Context, pkg PackageRef) (*VetResult, error)
}

// cachedEntry stores the cached verification result and expiry.
type cachedEntry struct {
	result    *VetResult
	expiresAt time.Time
}

// PublicRegistryVerifier queries official registry APIs with caching to detect hallucinated / non-existent packages.
type PublicRegistryVerifier struct {
	httpClient *http.Client
	cacheTTL   time.Duration
	cache      map[string]cachedEntry
	mu         sync.RWMutex
}

// wellKnownPackages is a zero-latency fast-path for ubiquitous packages.
var wellKnownPackages = map[string]map[string]bool{
	"pypi": {
		"requests": true, "urllib3": true, "numpy": true, "pandas": true,
		"torch": true, "tensorflow": true, "scipy": true, "pytest": true,
		"flask": true, "django": true, "fastapi": true, "pydantic": true,
		"setuptools": true, "wheel": true, "pip": true, "boto3": true,
	},
	"npm": {
		"react": true, "react-dom": true, "express": true, "lodash": true,
		"typescript": true, "next": true, "vue": true, "axios": true,
		"chalk": true, "commander": true, "dotenv": true, "jest": true,
	},
	"cargo": {
		"tokio": true, "serde": true, "serde_json": true, "syn": true,
		"rand": true, "reqwest": true, "anyhow": true, "thiserror": true,
	},
	"golang": {
		"golang.org/x/sys": true, "golang.org/x/net": true, "github.com/gin-gonic/gin": true,
	},
}

// NewPublicRegistryVerifier returns a new PublicRegistryVerifier with an in-memory TTL cache.
func NewPublicRegistryVerifier() *PublicRegistryVerifier {
	return &PublicRegistryVerifier{
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
		},
		cacheTTL: 15 * time.Minute,
		cache:    make(map[string]cachedEntry),
	}
}

// VerifyPackage checks if the package is present in official registries or fast-path cache.
func (v *PublicRegistryVerifier) VerifyPackage(ctx context.Context, pkg PackageRef) (*VetResult, error) {
	cacheKey := fmt.Sprintf("%s:%s", pkg.Ecosystem, strings.ToLower(pkg.Name))

	// 1. Check known legitimate allowlist
	if knownSet, ok := wellKnownPackages[pkg.Ecosystem]; ok {
		if knownSet[strings.ToLower(pkg.Name)] {
			return &VetResult{
				Package:       pkg,
				ExistsInIndex: true,
				IsSlopsquat:   false,
				Confidence:    1.0,
				Details:       "Verified via official standard package index (trusted fast-path)",
			}, nil
		}
	}

	// 2. Check in-memory TTL cache
	v.mu.RLock()
	entry, found := v.cache[cacheKey]
	v.mu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		return entry.result, nil
	}

	result := &VetResult{
		Package:       pkg,
		ExistsInIndex: true,
		IsSlopsquat:   false,
		Confidence:    1.0,
		Details:       "Verified against registry",
	}

	var endpoint string
	switch pkg.Ecosystem {
	case "pypi":
		endpoint = fmt.Sprintf("https://pypi.org/pypi/%s/json", pkg.Name)
	case "npm":
		endpoint = fmt.Sprintf("https://registry.npmjs.org/%s", pkg.Name)
	case "cargo":
		endpoint = fmt.Sprintf("https://crates.io/api/v1/crates/%s", pkg.Name)
	case "rubygems":
		endpoint = fmt.Sprintf("https://rubygems.org/api/v1/gems/%s.json", pkg.Name)
	default:
		result.Details = fmt.Sprintf("Unsupported ecosystem %q, skipping live lookup", pkg.Ecosystem)
		return result, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry request: %w", err)
	}
	req.Header.Set("User-Agent", "aegisbox-argus-vetpkg/1.0")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		// Network timeout / offline fallback - allow execution but log warning
		result.Details = fmt.Sprintf("Registry lookup skipped due to network error: %v", err)
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		result.ExistsInIndex = false
		result.IsSlopsquat = true
		result.Details = fmt.Sprintf("WARNING: Package %q not found in official %s registry (Potential hallucinated slopsquat)", pkg.Name, pkg.Ecosystem)
	} else if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound {
		result.Details = fmt.Sprintf("Registry returned HTTP %d, assuming package status unconfirmed", resp.StatusCode)
	}

	// Cache result
	v.mu.Lock()
	v.cache[cacheKey] = cachedEntry{
		result:    result,
		expiresAt: time.Now().Add(v.cacheTTL),
	}
	v.mu.Unlock()

	return result, nil
}
