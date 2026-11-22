package aisafety

import (
	"context"
	"time"
)

// ProbeCategory classifies deterministic and AI-integrated security checks.
type ProbeCategory string

const (
	ProbeIndirectPromptInjection ProbeCategory = "indirect_prompt_injection"
	ProbeRAGCrossTenantBleed     ProbeCategory = "rag_cross_tenant_bleed"
	ProbeToolArgPathTraversal    ProbeCategory = "tool_arg_path_traversal"
	ProbeToolArgSSRF             ProbeCategory = "tool_arg_ssrf"
	ProbeMCPScopeEscalation      ProbeCategory = "mcp_scope_escalation"
	ProbeSecretEgressCanary      ProbeCategory = "secret_egress_canary"
)

// AllProbeCategories returns the canonical ordered set of all 6 AI-safety probe categories.
func AllProbeCategories() []ProbeCategory {
	return []ProbeCategory{
		ProbeIndirectPromptInjection,
		ProbeRAGCrossTenantBleed,
		ProbeToolArgPathTraversal,
		ProbeToolArgSSRF,
		ProbeMCPScopeEscalation,
		ProbeSecretEgressCanary,
	}
}

// TargetKind constants define strictly local target modes.
const (
	TargetKindHTTPLocal = "http-local"
	TargetKindMCPStdio  = "mcp-stdio"
	TargetKindCLILocal  = "cli-local"
)

// TargetSpec defines a strictly local target (enforced loopback / STDIO only).
type TargetSpec struct {
	Kind               string        `json:"kind"`                           // "http-local" | "mcp-stdio" | "cli-local"
	Endpoint           string        `json:"endpoint,omitempty"`             // Must resolve strictly to 127.0.0.1 or ::1 (or unix:// local socket)
	Command            []string      `json:"command,omitempty"`              // Local MCP/CLI command run inside sandbox
	Timeout            time.Duration `json:"timeout"`                        // Per-suite timeout (defaults to 30s)
	AllowDegradedLocal bool          `json:"allow_degraded_local,omitempty"` // Explicit AEG-01 degraded Tier-1 opt-in when microVM unavailable
	TraceDir           string        `json:"trace_dir,omitempty"`            // Override flightdeck JSONL trace directory (defaults to ~/.flightdeck/traces)
}

// ProbeFinding captures ONLY a proven, reproducible security break (no speculative noise).
type ProbeFinding struct {
	ProbeID        string        `json:"probe_id"`
	Category       ProbeCategory `json:"category"`
	Proven         bool          `json:"proven"`                    // Must be true to surface in default output
	Summary        string        `json:"summary"`                   // Calm 1-line description
	OffendingInput string        `json:"offending_input"`           // Minimal sanitized reproducer
	ObservedEffect string        `json:"observed_effect"`           // e.g. "Tool 'refund_order' invoked without admin scope"
	FixPatchHint   string        `json:"fix_patch_hint"`            // Copy-pasteable code snippet / remediation
	WhyOneLiner    string        `json:"why_one_liner"`             // Calm 1-sentence intuition
	DeepWhy        string        `json:"deep_why"`                  // Detailed threat model & precedent (shown with --why)
	ReplayTraceID  string        `json:"replay_trace_id,omitempty"` // flightdeck trace ID
}

// CategorySummary aggregates probe pass/fail counts per ProbeCategory.
type CategorySummary struct {
	Category ProbeCategory `json:"category"`
	Total    int           `json:"total"`
	Passed   int           `json:"passed"`
	Failed   int           `json:"failed"`
}

// SuiteReport summarizes an entire local AI-safety adversarial test run.
type SuiteReport struct {
	Target         TargetSpec        `json:"target"`
	IsolationMode  string            `json:"isolation_mode"`
	TotalProbes    int               `json:"total_probes"`
	PassedProbes   int               `json:"passed_probes"`
	ProvenFailures int               `json:"proven_failures"`
	Duration       time.Duration     `json:"duration"`
	Categories     []CategorySummary `json:"categories"`
	Findings       []ProbeFinding    `json:"findings"` // Strictly proven findings only
	ReplayTraceID  string            `json:"replay_trace_id,omitempty"`
	TracePath      string            `json:"trace_path,omitempty"`
}

// Harness executes deterministic abuse probes against a strictly local dev target.
type Harness interface {
	ValidateLocalTarget(spec TargetSpec) error
	RunSuite(ctx context.Context, spec TargetSpec, categories []ProbeCategory) ([]ProbeFinding, error)
}
