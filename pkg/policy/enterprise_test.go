package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnterprisePolicy_PrecedenceHierarchy(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Machine policy: Enforce Standard, Disable Permissive, Allow *.github.com
	machinePolicyPath := filepath.Join(tempDir, "machine_policy.json")
	machineJSON := []byte(`{
		"minimum_profile": "standard",
		"disable_permissive_mode": true,
		"allowlist_egress_domains": ["*.github.com", "registry.npmjs.org"],
		"enforce_locksmith_biometrics": true
	}`)
	if err := os.WriteFile(machinePolicyPath, machineJSON, 0600); err != nil {
		t.Fatalf("failed to write machine policy: %v", err)
	}

	// 2. User policy attempts to set permissive
	userConfigPath := filepath.Join(tempDir, "user_config.json")
	userJSON := []byte(`{
		"minimum_profile": "permissive"
	}`)
	if err := os.WriteFile(userConfigPath, userJSON, 0600); err != nil {
		t.Fatalf("failed to write user policy: %v", err)
	}

	engine := NewEnterprisePolicyEngine(machinePolicyPath)
	resolved, err := engine.ResolvePolicy("", userConfigPath)
	if err != nil {
		t.Fatalf("failed to resolve policy: %v", err)
	}

	if !resolved.MDMEnforced {
		t.Errorf("expected MDMEnforced to be true")
	}

	if !resolved.PermissiveDisabled {
		t.Errorf("expected PermissiveDisabled to be true")
	}

	if resolved.EffectiveProfile != PostureStandard {
		t.Errorf("expected EffectiveProfile 'standard', got: %s", resolved.EffectiveProfile)
	}

	if len(resolved.AuditWarnings) == 0 {
		t.Errorf("expected audit warning regarding user permissive override attempt")
	}

	// 3. Verify ValidateProfileChange blocks switching to permissive
	err = engine.ValidateProfileChange(resolved, PosturePermissive)
	if err == nil {
		t.Errorf("expected error when validating switch to permissive under MDM lock")
	}
}

func TestEnterprisePolicy_WorkspaceTightening(t *testing.T) {
	tempDir := t.TempDir()

	// Machine policy: Standard
	machinePolicyPath := filepath.Join(tempDir, "machine_policy.json")
	machineJSON := []byte(`{"minimum_profile": "standard"}`)
	_ = os.WriteFile(machinePolicyPath, machineJSON, 0600)

	// Workspace policy in .aegisbox/policy.json tightens to microvm-hardened
	wsDir := filepath.Join(tempDir, "repo")
	_ = os.MkdirAll(filepath.Join(wsDir, ".aegisbox"), 0700)
	wsJSON := []byte(`{"minimum_profile": "microvm-hardened"}`)
	_ = os.WriteFile(filepath.Join(wsDir, ".aegisbox", "policy.json"), wsJSON, 0600)

	engine := NewEnterprisePolicyEngine(machinePolicyPath)
	resolved, err := engine.ResolvePolicy(wsDir, "")
	if err != nil {
		t.Fatalf("failed to resolve policy: %v", err)
	}

	if resolved.EffectiveProfile != PostureMicroVMHardened {
		t.Errorf("expected workspace to tighten to microvm-hardened, got: %s", resolved.EffectiveProfile)
	}
}

func TestEnterprisePolicy_DomainAllowlist(t *testing.T) {
	resolved := &ResolvedPolicy{
		AllowedDomains: []string{"*.github.com", "registry.npmjs.org", "api.openai.com"},
	}

	if !resolved.DomainAllowed("github.com") {
		t.Errorf("expected github.com to be allowed by *.github.com")
	}
	if !resolved.DomainAllowed("api.github.com") {
		t.Errorf("expected api.github.com to be allowed by *.github.com")
	}
	if !resolved.DomainAllowed("registry.npmjs.org") {
		t.Errorf("expected registry.npmjs.org to be allowed")
	}
	if resolved.DomainAllowed("evil-exfil.attacker.com") {
		t.Errorf("expected evil-exfil.attacker.com to be BLOCKED")
	}
}
