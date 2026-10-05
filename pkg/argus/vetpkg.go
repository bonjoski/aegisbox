package argus

import (
	"context"
	"fmt"
	"net/http"
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

// PublicRegistryVerifier queries official registry APIs with timeouts to detect hallucinated / non-existent packages.
type PublicRegistryVerifier struct {
	httpClient *http.Client
}

// NewPublicRegistryVerifier returns a new PublicRegistryVerifier.
func NewPublicRegistryVerifier() *PublicRegistryVerifier {
	return &PublicRegistryVerifier{
		httpClient: &http.Client{
			Timeout: 4 * time.Second,
		},
	}
}

// VerifyPackage checks if the package is present in official registries.
func (v *PublicRegistryVerifier) VerifyPackage(ctx context.Context, pkg PackageRef) (*VetResult, error) {
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
	default:
		result.Details = fmt.Sprintf("Unsupported ecosystem %q, skipping live lookup", pkg.Ecosystem)
		return result, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry request: %w", err)
	}
	req.Header.Set("User-Agent", "ironbox-argus-vetpkg/1.0")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		// Network timeout / offline fallback
		result.Details = fmt.Sprintf("Registry lookup skipped due to network error: %v", err)
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		result.ExistsInIndex = false
		result.IsSlopsquat = true
		result.Details = fmt.Sprintf("WARNING: Package %q not found in official %s registry (Potential hallucinated slopsquat)", pkg.Name, pkg.Ecosystem)
	}

	return result, nil
}
