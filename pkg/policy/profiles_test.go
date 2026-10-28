package policy

import (
	"testing"
)

func TestResolveProfileDomains(t *testing.T) {
	tests := []struct {
		profile     string
		expectLen   int
		shouldErr   bool
		sampleCheck string
	}{
		{"standard", len(StandardRegistryDomains), false, "proxy.golang.org"},
		{"go", len(GoRegistryDomains), false, "proxy.golang.org"},
		{"rust", len(RustRegistryDomains), false, "crates.io"},
		{"node", len(NodeRegistryDomains), false, "registry.npmjs.org"},
		{"python", len(PythonRegistryDomains), false, "pypi.org"},
		{"strict", len(StrictRegistryDomains), false, "github.com"},
		{"airgap", 0, false, ""},
		{"unknown-profile-xyz", 0, true, ""},
	}

	for _, tt := range tests {
		domains, err := ResolveProfileDomains(tt.profile)
		if tt.shouldErr {
			if err == nil {
				t.Errorf("expected error for profile %q, got nil", tt.profile)
			}
			continue
		}

		if err != nil {
			t.Errorf("unexpected error for profile %q: %v", tt.profile, err)
			continue
		}

		if len(domains) != tt.expectLen {
			t.Errorf("profile %q: expected %d domains, got %d", tt.profile, tt.expectLen, len(domains))
		}

		if tt.sampleCheck != "" {
			found := false
			for _, d := range domains {
				if d == tt.sampleCheck {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("profile %q: expected to contain %q", tt.profile, tt.sampleCheck)
			}
		}
	}
}
