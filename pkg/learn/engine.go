package learn

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bonjoski/aegisbox/pkg/aisafety"
)

// RunOptions configures a local `aegisbox learn` kata execution.
type RunOptions struct {
	KataID       string
	Check        bool   // Run with the 5-line paved-road fix verified
	Why          bool   // Include full threat model & real-world precedent
	UseOllama    bool   // Optional local Ollama loopback responder (127.0.0.1:11434)
	OllamaModel  string // Optional Ollama model tag (default llama3.2)
	TraceDir     string // Override flightdeck JSONL trace dir
	WorkspaceDir string // Optional explicit workspace dir (ephemeral 0700 temp dir if empty)
}

// KataResult captures the structured result of running a 2-minute local security kata.
type KataResult struct {
	Kata            KataMetadata  `json:"kata"`
	Mode            string        `json:"mode"` // "break" | "check"
	Passed          bool          `json:"passed"`
	AttackSucceeded bool          `json:"attack_succeeded"`
	ObservedEffect  string        `json:"observed_effect"`
	FixPatchHint    string        `json:"fix_patch_hint"`
	WhyOneLiner     string        `json:"why_one_liner"`
	DeepWhy         string        `json:"deep_why,omitempty"`
	LLMBackend      string        `json:"llm_backend"`
	DecoyHomeUsed   string        `json:"decoy_home_used"`
	ReplayTraceID   string        `json:"replay_trace_id"`
	TracePath       string        `json:"trace_path"`
	Duration        time.Duration `json:"duration"`
}

// Engine manages and executes the 5 offline 2-minute security katas.
type Engine struct {
	specs map[string]kataSpec
	order []string
}

// NewEngine initializes the Kata Engine with all 5 canonical local security katas.
func NewEngine() *Engine {
	specs := allKataSpecs()
	m := make(map[string]kataSpec, len(specs))
	order := make([]string, 0, len(specs))
	for _, s := range specs {
		m[s.Meta.ID] = s
		order = append(order, s.Meta.ID)
	}
	return &Engine{specs: m, order: order}
}

// ListKatas returns ordered metadata for all 5 available katas.
func (e *Engine) ListKatas() []KataMetadata {
	out := make([]KataMetadata, 0, len(e.order))
	for _, id := range e.order {
		out = append(out, e.specs[id].Meta)
	}
	return out
}

// RunKata executes a single kata inside an isolated ephemeral 0700 os.OpenRoot workspace
// with zero host $HOME access and zero WAN egress, saving a redacted Flightdeck replay trace.
// When opts.Check is true and opts.WorkspaceDir is set, RunKata evaluates the developer's
// edited fix inside that confined workspace via os.OpenRoot instead of running a synthetic pass.
func (e *Engine) RunKata(ctx context.Context, opts RunOptions) (*KataResult, error) {
	if opts.Check && strings.TrimSpace(opts.WorkspaceDir) != "" {
		return e.EvaluateWorkspace(ctx, opts)
	}
	if strings.TrimSpace(opts.WorkspaceDir) != "" {
		if _, err := validateSafeWorkspaceDir(opts.WorkspaceDir, true); err != nil {
			return nil, err
		}
	}

	spec, ok := e.specs[strings.TrimSpace(opts.KataID)]
	if !ok {
		return nil, fmt.Errorf("unknown kata %q (run `aegisbox learn list` to see available katas)", opts.KataID)
	}

	var llm LLMResponder = NewDeterministicMockLLM()
	if opts.UseOllama {
		ollama, err := NewOllamaResponder(opts.OllamaModel)
		if err != nil {
			return nil, fmt.Errorf("init local Ollama responder: %w", err)
		}
		llm = ollama
	}

	ws, err := NewKataWorkspace(spec.Meta.ID, opts.WorkspaceDir)
	if err != nil {
		return nil, fmt.Errorf("provision isolated kata workspace: %w", err)
	}
	defer ws.Close()

	start := time.Now()
	outcome, err := spec.Run(ctx, ws, llm, opts.Check)
	if err != nil {
		return nil, fmt.Errorf("execute kata %s: %w", spec.Meta.ID, err)
	}
	duration := time.Since(start)

	mode := "break"
	passed := outcome.AttackSucceeded // In "break" mode we demonstrate the exploit cleanly.
	if opts.Check {
		mode = "check"
		passed = outcome.FixVerified && !outcome.AttackSucceeded
	}

	traceID := aisafety.NewTraceID()
	events := append([]aisafety.TraceEvent{
		{
			Timestamp: time.Now().UTC(),
			EventType: "signal",
			Data:      fmt.Sprintf("kata_start id=%s mode=%s backend=%s airgap=true", spec.Meta.ID, mode, llm.Name()),
		},
	}, outcome.StepLog...)
	events = append(events, aisafety.TraceEvent{
		Timestamp: time.Now().UTC(),
		EventType: "signal",
		Data:      fmt.Sprintf("kata_end id=%s mode=%s passed=%v attack_succeeded=%v", spec.Meta.ID, mode, passed, outcome.AttackSucceeded),
	})

	tracePath, err := aisafety.WriteRedactedTrace(opts.TraceDir, traceID, events, outcome.SecretsToRedact...)
	if err != nil {
		return nil, fmt.Errorf("write redacted kata replay trace: %w", err)
	}

	res := &KataResult{
		Kata:            spec.Meta,
		Mode:            mode,
		Passed:          passed,
		AttackSucceeded: outcome.AttackSucceeded,
		ObservedEffect:  aisafety.RedactSecrets(outcome.ObservedEffect, outcome.SecretsToRedact...),
		FixPatchHint:    spec.Meta.FiveLineFix,
		WhyOneLiner:     spec.Meta.WhyOneLiner,
		LLMBackend:      llm.Name(),
		DecoyHomeUsed:   ws.DecoyHome,
		ReplayTraceID:   traceID,
		TracePath:       tracePath,
		Duration:        duration,
	}
	if opts.Why {
		res.DeepWhy = spec.Meta.DeepWhy
	}
	return res, nil
}

// FormatKataList renders all 5 katas in calm UB-CLI-v2 format.
func FormatKataList(katas []KataMetadata) string {
	var sb strings.Builder
	sb.WriteString("Aegisbox 2-Minute Local Security Katas (100% offline, zero API keys)\n\n")
	for _, k := range katas {
		fmt.Fprintf(&sb, "  %-26s [%s] (%s) — %s\n", k.ID, k.Domain, k.PortfolioTools, k.Title)
		fmt.Fprintf(&sb, "    %s\n", k.Summary)
	}
	sb.WriteString("\nRun a kata:\n")
	sb.WriteString("  aegisbox learn kata-03-rag-injection\n")
	sb.WriteString("  aegisbox learn kata-03-rag-injection --check\n")
	sb.WriteString("  aegisbox learn kata-03-rag-injection --why\n")
	return sb.String()
}

// FormatKataResult renders a single kata execution in calm UB-CLI-v2 Fix-Forward style.
func FormatKataResult(res *KataResult, showWhy bool) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Kata: %s — %s (%s, %s)\n", res.Kata.ID, res.Kata.Title, res.Mode, res.LLMBackend)

	if res.Mode == "break" {
		fmt.Fprintf(&sb, "  ✗ EXPLOIT REPRODUCED: %s\n", aisafety.StripANSI(res.ObservedEffect))
		fmt.Fprintf(&sb, "    Fix:  Apply the 5-line paved-road defense (%s):\n", res.Kata.PortfolioTools)
		for _, line := range strings.Split(res.FixPatchHint, "\n") {
			fmt.Fprintf(&sb, "          %s\n", line)
		}
		fmt.Fprintf(&sb, "    Next: Run `aegisbox learn %s --check` to verify the fix turns green.\n", res.Kata.ID)
	} else if res.Passed {
		fmt.Fprintf(&sb, "  ✓ PASS: %s\n", aisafety.StripANSI(res.ObservedEffect))
	} else {
		fmt.Fprintf(&sb, "  ✗ CHECK FAILED: %s\n", aisafety.StripANSI(res.ObservedEffect))
		if strings.TrimSpace(res.FixPatchHint) != "" {
			fmt.Fprintf(&sb, "    Fix:  Apply the paved-road defense (%s):\n", res.Kata.PortfolioTools)
			for _, line := range strings.Split(res.FixPatchHint, "\n") {
				fmt.Fprintf(&sb, "          %s\n", aisafety.StripANSI(line))
			}
		}
	}

	fmt.Fprintf(&sb, "    Why:  %s\n", aisafety.StripANSI(res.WhyOneLiner))
	if showWhy && res.Kata.DeepWhy != "" {
		fmt.Fprintf(&sb, "    Deep: %s\n", aisafety.StripANSI(res.Kata.DeepWhy))
	}
	if res.ReplayTraceID != "" {
		fmt.Fprintf(&sb, "    See:  Run `flightdeck replay %s` to step through the trace (or --why).\n", res.ReplayTraceID)
	}
	fmt.Fprintf(&sb, "\nCompleted in %s (air-gapped decoy workspace destroyed on exit)\n", res.Duration.Round(time.Millisecond))
	return sb.String()
}

// FormatKataJSON encodes either kata list or kata result as formatted JSON.
func FormatKataJSON(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
