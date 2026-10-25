package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SecurityPosture defines the isolation level enforced by policy.
type SecurityPosture string

const (
	PosturePermissive      SecurityPosture = "permissive"
	PostureStandard        SecurityPosture = "standard"
	PostureMicroVMHardened SecurityPosture = "microvm-hardened"
)

// PolicyConfig represents the enterprise configuration schema.
type PolicyConfig struct {
	MinimumProfile             SecurityPosture `json:"minimum_profile" yaml:"minimum_profile"`
	DisablePermissiveMode      bool            `json:"disable_permissive_mode" yaml:"disable_permissive_mode"`
	AllowlistEgressDomains     []string        `json:"allowlist_egress_domains" yaml:"allowlist_egress_domains"`
	AuditLogForwardingEndpoint string          `json:"audit_log_forwarding_endpoint,omitempty" yaml:"audit_log_forwarding_endpoint,omitempty"`
	EnforceLocksmithBiometrics bool            `json:"enforce_locksmith_biometrics" yaml:"enforce_locksmith_biometrics"`
}

// ResolvedPolicy is the effective combined policy after evaluating the hierarchy.
type ResolvedPolicy struct {
	EffectiveProfile       SecurityPosture `json:"effective_profile"`
	PermissiveDisabled     bool            `json:"permissive_disabled"`
	AllowedDomains         []string        `json:"allowed_domains"`
	MDMEnforced            bool            `json:"mdm_enforced"`
	EnforceBiometrics      bool            `json:"enforce_biometrics"`
	AuditEndpoint          string          `json:"audit_endpoint,omitempty"`
	AuditWarnings          []string        `json:"audit_warnings,omitempty"`
}

// EnterprisePolicyEngine resolves policies across machine, workspace, and user layers.
type EnterprisePolicyEngine struct {
	machinePolicyPath string
}

// NewEnterprisePolicyEngine initializes the policy engine.
func NewEnterprisePolicyEngine(customMachinePath string) *EnterprisePolicyEngine {
	if customMachinePath == "" {
		customMachinePath = defaultMachinePolicyPath()
	}
	return &EnterprisePolicyEngine{
		machinePolicyPath: customMachinePath,
	}
}

func defaultMachinePolicyPath() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Managed Preferences/com.bonjoski.aegisbox.json"
	case "windows":
		return `C:\ProgramData\Aegisbox\policy.json`
	default:
		return "/etc/aegisbox/policy.json"
	}
}

// ResolvePolicy evaluates the 3-tier hierarchy: Machine (Tier 1) > Workspace (Tier 2) > User (Tier 3).
func (e *EnterprisePolicyEngine) ResolvePolicy(workspaceDir, userConfigPath string) (*ResolvedPolicy, error) {
	resolved := &ResolvedPolicy{
		EffectiveProfile:   PostureStandard,
		PermissiveDisabled: false,
		AllowedDomains:     make([]string, 0),
		AuditWarnings:      make([]string, 0),
	}

	// 1. Load Tier 1: Machine Policy (Immutable MDM / GPO)
	if e.machinePolicyPath != "" {
		if data, err := os.ReadFile(e.machinePolicyPath); err == nil {
			var cfg PolicyConfig
			if err := json.Unmarshal(data, &cfg); err == nil {
				resolved.MDMEnforced = true
				resolved.PermissiveDisabled = cfg.DisablePermissiveMode
				resolved.EnforceBiometrics = cfg.EnforceLocksmithBiometrics
				resolved.AuditEndpoint = cfg.AuditLogForwardingEndpoint
				if cfg.MinimumProfile != "" {
					resolved.EffectiveProfile = cfg.MinimumProfile
				}
				resolved.AllowedDomains = append(resolved.AllowedDomains, cfg.AllowlistEgressDomains...)
			}
		}
	}

	// 2. Load Tier 2: Workspace Policy (.aegisbox/policy.json or policy.yaml)
	if workspaceDir != "" {
		wsPolicyPath := filepath.Join(workspaceDir, ".aegisbox", "policy.json")
		if data, err := os.ReadFile(wsPolicyPath); err == nil {
			var wsCfg PolicyConfig
			if err := json.Unmarshal(data, &wsCfg); err == nil {
				// Workspace can only TIGHTEN security
				if wsCfg.DisablePermissiveMode {
					resolved.PermissiveDisabled = true
				}
				if wsCfg.EnforceLocksmithBiometrics {
					resolved.EnforceBiometrics = true
				}
				if isMoreRestrictive(wsCfg.MinimumProfile, resolved.EffectiveProfile) {
					resolved.EffectiveProfile = wsCfg.MinimumProfile
				}
			}
		}
	}

	// 3. Load Tier 3: User Preference
	if userConfigPath != "" {
		if data, err := os.ReadFile(userConfigPath); err == nil {
			var userCfg PolicyConfig
			if err := json.Unmarshal(data, &userCfg); err == nil {
				// Attempt to bypass MDM?
				if resolved.PermissiveDisabled && userCfg.MinimumProfile == PosturePermissive {
					resolved.AuditWarnings = append(resolved.AuditWarnings,
						"User attempted to select 'permissive' profile, but machine MDM forbids permissive mode.")
				} else if isMoreRestrictive(userCfg.MinimumProfile, resolved.EffectiveProfile) {
					resolved.EffectiveProfile = userCfg.MinimumProfile
				}
			}
		}
	}

	return resolved, nil
}

// ValidateProfileChange ensures that a requested profile change does not violate MDM constraints.
func (e *EnterprisePolicyEngine) ValidateProfileChange(resolved *ResolvedPolicy, requested SecurityPosture) error {
	if resolved.PermissiveDisabled && requested == PosturePermissive {
		return fmt.Errorf("permissive profile is disabled by enterprise MDM/GPO policy")
	}

	if isLessRestrictive(requested, resolved.EffectiveProfile) {
		return fmt.Errorf("cannot switch to %s: minimum enforced posture is %s", requested, resolved.EffectiveProfile)
	}

	return nil
}

func postureRank(p SecurityPosture) int {
	switch p {
	case PostureMicroVMHardened:
		return 3
	case PostureStandard:
		return 2
	case PosturePermissive:
		return 1
	default:
		return 2
	}
}

func isMoreRestrictive(a, b SecurityPosture) bool {
	return postureRank(a) > postureRank(b)
}

func isLessRestrictive(a, b SecurityPosture) bool {
	return postureRank(a) < postureRank(b)
}

// DomainAllowed checks if a target domain is permitted by the egress allowlist.
func (r *ResolvedPolicy) DomainAllowed(targetDomain string) bool {
	if len(r.AllowedDomains) == 0 {
		return true // No explicit restriction
	}

	target := strings.ToLower(strings.TrimSpace(targetDomain))
	for _, pattern := range r.AllowedDomains {
		pat := strings.ToLower(strings.TrimSpace(pattern))
		if pat == "*" {
			return true
		}
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:] // e.g. ".github.com"
			if strings.HasSuffix(target, suffix) || target == pat[2:] {
				return true
			}
		} else if target == pat {
			return true
		}
	}

	return false
}
