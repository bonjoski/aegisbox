package aisafety

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/aegisbox/pkg/vmm"
)

const (
	defaultSuiteTimeout = 30 * time.Second
	maxResponseBytes    = 256 * 1024
)

// DefaultHarness is the concrete local AI-safety adversarial harness.
type DefaultHarness struct {
	Slots  *SlotSemaphore
	Probes []ProbeDefinition
}

// NewDefaultHarness creates a DefaultHarness with bounded concurrency (max 4 slots) and all 12 probes.
func NewDefaultHarness() *DefaultHarness {
	return &DefaultHarness{
		Slots:  NewSlotSemaphore(DefaultMaxConcurrentSlots),
		Probes: DefaultProbes(),
	}
}

// ValidateLocalTarget enforces strictly local loopback / local STDIO Safe Harbor constraints.
func (h *DefaultHarness) ValidateLocalTarget(spec TargetSpec) error {
	return ValidateLocalTarget(spec)
}

// RunSuite executes the requested probe categories (or all 6 when categories is empty)
// and returns ONLY proven findings.
func (h *DefaultHarness) RunSuite(ctx context.Context, spec TargetSpec, categories []ProbeCategory) ([]ProbeFinding, error) {
	report, err := h.RunSuiteWithReport(ctx, spec, categories)
	if err != nil {
		return nil, err
	}
	return report.Findings, nil
}

// RunSuiteWithReport executes the probe suite and returns a structured SuiteReport with
// per-category statistics, proven findings, and a redacted Flightdeck trace ID.
func (h *DefaultHarness) RunSuiteWithReport(ctx context.Context, spec TargetSpec, categories []ProbeCategory) (*SuiteReport, error) {
	if err := h.ValidateLocalTarget(spec); err != nil {
		return nil, err
	}

	kind := inferTargetKind(spec)
	spec.Kind = kind
	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = defaultSuiteTimeout
	}
	suiteCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Acquire bounded concurrency slot (max 4 active across N=8 callers).
	slots := h.Slots
	if slots == nil {
		slots = NewSlotSemaphore(DefaultMaxConcurrentSlots)
	}
	if err := slots.Acquire(suiteCtx); err != nil {
		return nil, fmt.Errorf("failed to acquire AI-safety concurrency slot: %w", err)
	}
	defer slots.Release()

	// Enforce AEG-01 isolation posture check for subprocess execution modes (mcp-stdio / cli-local).
	isolationMode, err := verifyIsolationPosture(suiteCtx, spec)
	if err != nil {
		return nil, err
	}

	selectedProbes := h.filterProbes(categories)
	traceID := NewTraceID()
	traceEvents := []TraceEvent{
		{
			Timestamp: time.Now().UTC(),
			EventType: "signal",
			Data:      fmt.Sprintf("aisafety_suite_start kind=%s isolation=%s probes=%d", kind, isolationMode, len(selectedProbes)),
		},
	}

	start := time.Now()
	catOrder, catStats := initCategoryStats(selectedProbes)
	var provenFindings []ProbeFinding

	switch kind {
	case TargetKindHTTPLocal:
		findings, events, err := h.runHTTPProbes(suiteCtx, spec, selectedProbes, traceID, catStats)
		if err != nil {
			return nil, err
		}
		provenFindings = findings
		traceEvents = append(traceEvents, events...)
	case TargetKindMCPStdio:
		findings, events, err := h.runMCPStdioProbes(suiteCtx, spec, selectedProbes, traceID, catStats)
		if err != nil {
			return nil, err
		}
		provenFindings = findings
		traceEvents = append(traceEvents, events...)
	case TargetKindCLILocal:
		findings, events, err := h.runCLILocalProbes(suiteCtx, spec, selectedProbes, traceID, catStats)
		if err != nil {
			return nil, err
		}
		provenFindings = findings
		traceEvents = append(traceEvents, events...)
	default:
		return nil, fmt.Errorf("%w: unsupported target kind %q", ErrInvalidTargetSpec, kind)
	}

	duration := time.Since(start)
	traceEvents = append(traceEvents, TraceEvent{
		Timestamp: time.Now().UTC(),
		EventType: "signal",
		Data:      fmt.Sprintf("aisafety_suite_end total=%d proven_failures=%d duration_ms=%d", len(selectedProbes), len(provenFindings), duration.Milliseconds()),
	})

	// Write Flightdeck-compatible JSONL trace with mandatory secret redaction before disk write.
	tracePath, traceErr := WriteRedactedTrace(spec.TraceDir, traceID, traceEvents)
	if traceErr != nil {
		return nil, fmt.Errorf("failed writing redacted replay trace: %w", traceErr)
	}

	orderedCats := make([]CategorySummary, 0, len(catOrder))
	for _, cat := range catOrder {
		orderedCats = append(orderedCats, *catStats[cat])
	}

	return &SuiteReport{
		Target:         spec,
		IsolationMode:  isolationMode,
		TotalProbes:    len(selectedProbes),
		PassedProbes:   len(selectedProbes) - len(provenFindings),
		ProvenFailures: len(provenFindings),
		Duration:       duration,
		Categories:     orderedCats,
		Findings:       provenFindings,
		ReplayTraceID:  traceID,
		TracePath:      tracePath,
	}, nil
}

func verifyIsolationPosture(ctx context.Context, spec TargetSpec) (string, error) {
	driver := vmm.NewPlatformDriver()
	if err := driver.VerifyPrerequisites(ctx); err == nil {
		return "microvm", nil
	}
	if spec.Kind == TargetKindHTTPLocal {
		// HTTP probing connects strictly to an already-running loopback socket via IP-pinned Dialer.Control.
		return "loopback-pinned-http", nil
	}
	if spec.AllowDegradedLocal {
		return "degraded-local", nil
	}
	return "", fmt.Errorf(
		"AEG-01 fail-closed: hardware microVM prerequisites unavailable for local subprocess target %q.\n"+
			"  Fix:  Provision the microVM appliance (`aegisbox doctor`) OR pass --allow-degraded-local to run in isolated Tier-1 local mode.\n"+
			"  Why:  Aegisbox never silently downgrades subprocess containment when hardware virtualization is unavailable.",
		strings.Join(spec.Command, " "),
	)
}

func (h *DefaultHarness) filterProbes(categories []ProbeCategory) []ProbeDefinition {
	probes := h.Probes
	if len(probes) == 0 {
		probes = DefaultProbes()
	}
	if len(categories) == 0 {
		return probes
	}
	allowed := make(map[ProbeCategory]bool, len(categories))
	for _, c := range categories {
		allowed[c] = true
	}
	out := make([]ProbeDefinition, 0, len(probes))
	for _, p := range probes {
		if allowed[p.Category] {
			out = append(out, p)
		}
	}
	return out
}

func initCategoryStats(probes []ProbeDefinition) ([]ProbeCategory, map[ProbeCategory]*CategorySummary) {
	var order []ProbeCategory
	stats := make(map[ProbeCategory]*CategorySummary)
	for _, p := range probes {
		if _, ok := stats[p.Category]; !ok {
			order = append(order, p.Category)
			stats[p.Category] = &CategorySummary{Category: p.Category}
		}
		stats[p.Category].Total++
	}
	return order, stats
}

func (h *DefaultHarness) runHTTPProbes(
	ctx context.Context,
	spec TargetSpec,
	probes []ProbeDefinition,
	traceID string,
	catStats map[ProbeCategory]*CategorySummary,
) ([]ProbeFinding, []TraceEvent, error) {
	resolved, err := ResolveAndPinLocalHTTPURL(ctx, spec.Endpoint)
	if err != nil {
		return nil, nil, err
	}
	client := NewLoopbackPinnedHTTPClient(10*time.Second, resolved.PinnedIP)

	var findings []ProbeFinding
	var events []TraceEvent

	for _, p := range probes {
		payloadBytes, err := json.Marshal(p.Request)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal probe %s: %w", p.ID, err)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, resolved.URL.String(), bytes.NewReader(payloadBytes))
		if err != nil {
			return nil, nil, fmt.Errorf("build request for probe %s: %w", p.ID, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Aegisbox-Probe-ID", p.ID)
		if p.Request.TenantID != "" {
			req.Header.Set("X-Tenant-ID", p.Request.TenantID)
		}

		events = append(events, TraceEvent{
			Timestamp: time.Now().UTC(),
			EventType: "stdin",
			ProbeID:   p.ID,
			Category:  string(p.Category),
			Data:      string(payloadBytes),
		})

		resp, err := client.Do(req)
		if err != nil {
			// If redirect was blocked for leaving loopback, fail closed immediately!
			if errors.Is(err, ErrNonLoopbackRedirect) || errors.Is(err, ErrNonLoopbackTarget) {
				return nil, nil, err
			}
			return nil, nil, fmt.Errorf("local HTTP target unreachable during probe %s: %w", p.ID, err)
		}
		bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		resp.Body.Close()
		if readErr != nil {
			return nil, nil, fmt.Errorf("read response for probe %s: %w", p.ID, readErr)
		}
		body := string(bodyBytes)

		events = append(events, TraceEvent{
			Timestamp: time.Now().UTC(),
			EventType: "stdout",
			ProbeID:   p.ID,
			Category:  string(p.Category),
			Data:      body,
		})

		if proven, effect := p.VerifyProof(body, resp.StatusCode); proven {
			catStats[p.Category].Failed++
			finding := ProbeFinding{
				ProbeID:        p.ID,
				Category:       p.Category,
				Proven:         true,
				Summary:        StripANSI(p.Summary),
				OffendingInput: RedactSecrets(p.OffendingInput),
				ObservedEffect: RedactSecrets(effect),
				FixPatchHint:   p.FixPatchHint,
				WhyOneLiner:    p.WhyOneLiner,
				DeepWhy:        p.DeepWhy,
				ReplayTraceID:  traceID,
			}
			findings = append(findings, finding)
			events = append(events, TraceEvent{
				Timestamp: time.Now().UTC(),
				EventType: "finding",
				ProbeID:   p.ID,
				Category:  string(p.Category),
				Data:      fmt.Sprintf("PROVEN: %s (%s)", finding.Summary, finding.ObservedEffect),
			})
		} else {
			catStats[p.Category].Passed++
		}
	}

	return findings, events, nil
}

type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

func (h *DefaultHarness) runMCPStdioProbes(
	ctx context.Context,
	spec TargetSpec,
	probes []ProbeDefinition,
	traceID string,
	catStats map[ProbeCategory]*CategorySummary,
) ([]ProbeFinding, []TraceEvent, error) {
	// Spawn local MCP server inside an isolated ephemeral 0700 temp HOME with sanitized env.
	ephemeralHome, err := os.MkdirTemp("", "aegisbox-aisafety-mcp-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create isolated MCP home: %w", err)
	}
	defer os.RemoveAll(ephemeralHome)
	_ = os.Chmod(ephemeralHome, 0700)

	cmd := exec.CommandContext(ctx, spec.Command[0], spec.Command[1:]...)
	cmd.Env = sanitizedLocalEnv(ephemeralHome)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("mcp stdin pipe: %w", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("mcp stdout pipe: %w", err)
	}
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start local MCP process %q: %w", spec.Command[0], err)
	}
	defer func() {
		_ = stdinPipe.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	reader := bufio.NewReaderSize(stdoutPipe, maxResponseBytes)
	sendRPC := func(req jsonRPCRequest) (string, error) {
		raw, err := json.Marshal(req)
		if err != nil {
			return "", err
		}
		if _, err := stdinPipe.Write(append(raw, '\n')); err != nil {
			return "", err
		}
		line, err := readLineWithContext(ctx, reader)
		if err != nil {
			return "", err
		}
		return line, nil
	}

	var events []TraceEvent
	// Step 1: MCP JSON-RPC initialize handshake (best-effort; some lightweight servers accept direct tools/call).
	initReq := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: map[string]any{
			"protocolVersion": "2024-11-05",
			"clientInfo":      map[string]string{"name": "aegisbox-aisafety", "version": "1.0.0"},
		},
	}
	if initResp, err := sendRPC(initReq); err == nil {
		events = append(events, TraceEvent{
			Timestamp: time.Now().UTC(),
			EventType: "mcp_call",
			Data:      "initialize -> " + initResp,
		})
	} else {
		return nil, nil, fmt.Errorf("local MCP server failed initialize handshake: %w (stderr: %s)", err, RedactSecrets(stderrBuf.String()))
	}

	var findings []ProbeFinding
	rpcID := 2
	for _, p := range probes {
		toolName := p.Request.Tool
		if toolName == "" {
			toolName = "invoke"
		}
		args := make(map[string]any, len(p.Request.Args)+3)
		for k, v := range p.Request.Args {
			args[k] = v
		}
		if p.Request.Prompt != "" {
			args["prompt"] = p.Request.Prompt
		}
		if p.Request.Document != "" {
			args["document"] = p.Request.Document
		}
		if p.Request.TenantID != "" {
			args["caller_tenant_id"] = p.Request.TenantID
		}

		callReq := jsonRPCRequest{
			JSONRPC: "2.0",
			ID:      rpcID,
			Method:  "tools/call",
			Params: map[string]any{
				"name":      toolName,
				"arguments": args,
			},
		}
		rpcID++

		reqJSON, _ := json.Marshal(callReq)
		events = append(events, TraceEvent{
			Timestamp: time.Now().UTC(),
			EventType: "mcp_call",
			ProbeID:   p.ID,
			Category:  string(p.Category),
			Data:      string(reqJSON),
		})

		respLine, err := sendRPC(callReq)
		if err != nil {
			return nil, nil, fmt.Errorf("MCP probe %s (%s) failed: %w", p.ID, toolName, err)
		}
		events = append(events, TraceEvent{
			Timestamp: time.Now().UTC(),
			EventType: "stdout",
			ProbeID:   p.ID,
			Category:  string(p.Category),
			Data:      respLine,
		})

		if proven, effect := p.VerifyProof(respLine, http.StatusOK); proven {
			catStats[p.Category].Failed++
			finding := ProbeFinding{
				ProbeID:        p.ID,
				Category:       p.Category,
				Proven:         true,
				Summary:        StripANSI(p.Summary),
				OffendingInput: RedactSecrets(p.OffendingInput),
				ObservedEffect: RedactSecrets(effect),
				FixPatchHint:   p.FixPatchHint,
				WhyOneLiner:    p.WhyOneLiner,
				DeepWhy:        p.DeepWhy,
				ReplayTraceID:  traceID,
			}
			findings = append(findings, finding)
			events = append(events, TraceEvent{
				Timestamp: time.Now().UTC(),
				EventType: "finding",
				ProbeID:   p.ID,
				Category:  string(p.Category),
				Data:      fmt.Sprintf("PROVEN: %s (%s)", finding.Summary, finding.ObservedEffect),
			})
		} else {
			catStats[p.Category].Passed++
		}
	}

	return findings, events, nil
}

func (h *DefaultHarness) runCLILocalProbes(
	ctx context.Context,
	spec TargetSpec,
	probes []ProbeDefinition,
	traceID string,
	catStats map[ProbeCategory]*CategorySummary,
) ([]ProbeFinding, []TraceEvent, error) {
	ephemeralHome, err := os.MkdirTemp("", "aegisbox-aisafety-cli-*")
	if err != nil {
		return nil, nil, fmt.Errorf("create isolated CLI home: %w", err)
	}
	defer os.RemoveAll(ephemeralHome)
	_ = os.Chmod(ephemeralHome, 0700)

	var findings []ProbeFinding
	var events []TraceEvent

	for _, p := range probes {
		payloadBytes, _ := json.Marshal(p.Request)
		cmd := exec.CommandContext(ctx, spec.Command[0], spec.Command[1:]...)
		cmd.Env = sanitizedLocalEnv(ephemeralHome)
		cmd.Stdin = bytes.NewReader(payloadBytes)
		var outBuf bytes.Buffer
		cmd.Stdout = &outBuf
		cmd.Stderr = &outBuf

		_ = cmd.Run()
		body := outBuf.String()
		if len(body) > maxResponseBytes {
			body = body[:maxResponseBytes]
		}

		events = append(events,
			TraceEvent{Timestamp: time.Now().UTC(), EventType: "stdin", ProbeID: p.ID, Category: string(p.Category), Data: string(payloadBytes)},
			TraceEvent{Timestamp: time.Now().UTC(), EventType: "stdout", ProbeID: p.ID, Category: string(p.Category), Data: body},
		)

		if proven, effect := p.VerifyProof(body, http.StatusOK); proven {
			catStats[p.Category].Failed++
			findings = append(findings, ProbeFinding{
				ProbeID:        p.ID,
				Category:       p.Category,
				Proven:         true,
				Summary:        StripANSI(p.Summary),
				OffendingInput: RedactSecrets(p.OffendingInput),
				ObservedEffect: RedactSecrets(effect),
				FixPatchHint:   p.FixPatchHint,
				WhyOneLiner:    p.WhyOneLiner,
				DeepWhy:        p.DeepWhy,
				ReplayTraceID:  traceID,
			})
		} else {
			catStats[p.Category].Passed++
		}
	}
	return findings, events, nil
}

func sanitizedLocalEnv(ephemeralHome string) []string {
	tmpDir := filepath.Join(ephemeralHome, "tmp")
	_ = os.MkdirAll(tmpDir, 0700)
	pathVal := os.Getenv("PATH")
	if pathVal == "" {
		pathVal = "/usr/bin:/bin:/usr/local/bin"
	}
	return []string{
		"PATH=" + pathVal,
		"HOME=" + ephemeralHome,
		"TMPDIR=" + tmpDir,
		"LOCKSMITH_MOCK_BACKEND=1",
		"AEGISBOX_AISAFETY_SANDBOX=1",
	}
}

func readLineWithContext(ctx context.Context, r *bufio.Reader) (string, error) {
	type res struct {
		line string
		err  error
	}
	ch := make(chan res, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- res{line: strings.TrimSpace(line), err: err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case out := <-ch:
		return out.line, out.err
	}
}

// FormatReport renders SuiteReport in calm UB-CLI-v2 Fix-Forward style.
func FormatReport(report *SuiteReport, showWhy bool) string {
	var sb strings.Builder
	targetDesc := report.Target.Endpoint
	if targetDesc == "" && len(report.Target.Command) > 0 {
		targetDesc = strings.Join(report.Target.Command, " ")
	}
	fmt.Fprintf(&sb, "Running %d local AI-safety probes against %s (%s)...\n",
		report.TotalProbes, report.Target.Kind, StripANSI(targetDesc))

	findingsByCat := make(map[ProbeCategory][]ProbeFinding)
	for _, f := range report.Findings {
		if f.Proven {
			findingsByCat[f.Category] = append(findingsByCat[f.Category], f)
		}
	}

	for _, cat := range report.Categories {
		catFindings := findingsByCat[cat.Category]
		if len(catFindings) == 0 {
			fmt.Fprintf(&sb, "  ✓ %s (%d/%d passed)\n", cat.Category, cat.Passed, cat.Total)
			continue
		}
		for _, f := range catFindings {
			fmt.Fprintf(&sb, "  ✗ %s [%s]: %s\n", f.Category, f.ProbeID, StripANSI(f.Summary))
			fmt.Fprintf(&sb, "    Hit:  %s\n", StripANSI(f.ObservedEffect))
			fmt.Fprintf(&sb, "    Fix:  %s\n", StripANSI(f.FixPatchHint))
			fmt.Fprintf(&sb, "    Why:  %s\n", StripANSI(f.WhyOneLiner))
			if showWhy && f.DeepWhy != "" {
				fmt.Fprintf(&sb, "    Deep: %s\n", StripANSI(f.DeepWhy))
			}
			if f.ReplayTraceID != "" {
				fmt.Fprintf(&sb, "    See:  Run `flightdeck replay %s` to watch the exact call sequence (or --why).\n", f.ReplayTraceID)
			}
		}
	}

	fmt.Fprintf(&sb, "\nResult: %d passed, %d proven failure(s) (%s)\n",
		report.PassedProbes, report.ProvenFailures, report.Duration.Round(time.Millisecond))
	return sb.String()
}

// FormatReportJSON encodes SuiteReport as formatted JSON.
func FormatReportJSON(report *SuiteReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
