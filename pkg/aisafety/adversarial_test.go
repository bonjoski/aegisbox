package aisafety

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestValidateLocalTarget_BlocksPublicIPAndDNSRebinding verifies strict PANW Safe Harbor
// loopback pinning: public hosts, IMDS, 0.0.0.0, IPv4-mapped IPv6, NAT64, DNS rebinding
// domains, remote binaries, and 302 redirects from 127.0.0.1 -> 1.1.1.1 all fail closed.
func TestValidateLocalTarget_BlocksPublicIPAndDNSRebinding(t *testing.T) {
	harness := NewDefaultHarness()

	blockedEndpoints := []string{
		"https://example.com/api/chat",
		"http://1.1.1.1/api/chat",
		"http://169.254.169.254/latest/meta-data/",
		"http://0.0.0.0:8080/api/chat",
		"http://[::]:8080/api/chat",
		"http://[::ffff:8.8.8.8]:8080/api/chat",
		"http://[::ffff:169.254.169.254]/latest/meta-data/",
		"http://[::ffff:127.0.0.1]:8080/api/chat",
		"http://[64:ff9b::127.0.0.1]:8080/api/chat",
		"http://127.0.0.1.nip.io:8080/api/chat",
		"http://0x7f000001:8080/api/chat",
		"http://2130706433:8080/api/chat",
		"http://user:pass@127.0.0.1:8080/api/chat",
		"file:///etc/passwd",
		"gopher://127.0.0.1:8080/",
	}

	for _, ep := range blockedEndpoints {
		err := harness.ValidateLocalTarget(TargetSpec{
			Kind:     TargetKindHTTPLocal,
			Endpoint: ep,
		})
		if err == nil {
			t.Errorf("expected fail-closed rejection for non-loopback endpoint %q, got nil", ep)
		}
	}

	// Verify allowed strictly loopback endpoints pass validation.
	allowedEndpoints := []string{
		"http://127.0.0.1:8080/api/chat",
		"http://localhost:8080/api/chat",
		"http://[::1]:8080/api/chat",
	}
	for _, ep := range allowedEndpoints {
		if err := harness.ValidateLocalTarget(TargetSpec{
			Kind:     TargetKindHTTPLocal,
			Endpoint: ep,
		}); err != nil {
			t.Errorf("expected strictly loopback endpoint %q to be allowed, got error: %v", ep, err)
		}
	}

	// Verify remote-pivoting commands in mcp-stdio fail closed.
	for _, cmd := range [][]string{{"ssh", "victim@example.com"}, {"curl", "https://example.com"}, {"nc", "1.1.1.1", "80"}} {
		if err := harness.ValidateLocalTarget(TargetSpec{
			Kind:    TargetKindMCPStdio,
			Command: cmd,
		}); err == nil {
			t.Errorf("expected fail-closed rejection for remote command %v", cmd)
		}
	}

	// Live HTTP 302 redirect test: 127.0.0.1 -> http://1.1.1.1/ MUST fail closed!
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://1.1.1.1/escaped", http.StatusFound)
	}))
	defer redirector.Close()

	_, err := harness.RunSuiteWithReport(context.Background(), TargetSpec{
		Kind:     TargetKindHTTPLocal,
		Endpoint: redirector.URL,
		TraceDir: t.TempDir(),
	}, []ProbeCategory{ProbeIndirectPromptInjection})
	if err == nil {
		t.Fatalf("expected 302 redirect from 127.0.0.1 -> 1.1.1.1 to fail closed, got nil")
	}
	if !errors.Is(err, ErrNonLoopbackRedirect) && !errors.Is(err, ErrNonLoopbackTarget) {
		t.Fatalf("expected ErrNonLoopbackRedirect/ErrNonLoopbackTarget, got: %v", err)
	}
}

// TestAISafetyHarness_RedactsRealSecretInReplay injects simulated OpenAI, Anthropic, and AWS
// credentials plus ANSI escape sequences into a local mock app response and asserts ZERO raw
// secret bytes or ANSI escapes are written to the Flightdeck JSONL trace on disk.
func TestAISafetyHarness_RedactsRealSecretInReplay(t *testing.T) {
	simOpenAI := "sk-proj-TestRealLookingOpenAIKey9876543210ABCDEF"
	simAWS := "AKIAIOSFODNN7EXAMPLE"
	simAnthropic := "sk-ant-api03-FakeAnthropicSecretToken1234567890"
	ansiHijack := "\x1b]52;c;Y2xpcGJvYXJk\x07\x1b[31mLEAK\x1b[0m"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","output":"%s openai=%s aws=%s anthropic=%s canary=%s"}`,
			ansiHijack, simOpenAI, simAWS, simAnthropic, CanaryTokenValue)
	}))
	defer srv.Close()

	traceDir := t.TempDir()
	harness := NewDefaultHarness()
	report, err := harness.RunSuiteWithReport(context.Background(), TargetSpec{
		Kind:     TargetKindHTTPLocal,
		Endpoint: srv.URL,
		TraceDir: traceDir,
	}, []ProbeCategory{ProbeSecretEgressCanary})
	if err != nil {
		t.Fatalf("RunSuiteWithReport failed: %v", err)
	}
	if report.ProvenFailures == 0 {
		t.Fatalf("expected proven secret_egress_canary failures, got 0")
	}
	if report.TracePath == "" {
		t.Fatalf("expected non-empty TracePath")
	}

	rawTrace, err := os.ReadFile(report.TracePath)
	if err != nil {
		t.Fatalf("failed reading trace file %q: %v", report.TracePath, err)
	}
	traceStr := string(rawTrace)

	for name, secret := range map[string]string{
		"OpenAI":    simOpenAI,
		"AWS":       simAWS,
		"Anthropic": simAnthropic,
	} {
		if strings.Contains(traceStr, secret) {
			t.Errorf("SECURITY VIOLATION: raw %s secret leaked into Flightdeck trace %q", name, report.TracePath)
		}
	}
	if strings.Contains(traceStr, "\x1b") {
		t.Errorf("SECURITY VIOLATION: raw ANSI escape sequence survived in trace %q", report.TracePath)
	}
	if !strings.Contains(traceStr, RedactedPlaceholder) {
		t.Errorf("expected %s placeholder in redacted trace, got:\n%s", RedactedPlaceholder, traceStr)
	}

	// Verify rendered calm output also has zero raw ANSI codes.
	rendered := FormatReport(report, true)
	if strings.Contains(rendered, "\x1b") {
		t.Errorf("rendered report contained raw ANSI escape bytes")
	}
}

// TestAISafetyHarness_ConcurrencySlotBoundsN8 fires 8 concurrent suite runs sharing a single
// harness semaphore (max 4 slots) and asserts peak active slots never exceed 4 and all 8 finish cleanly.
func TestAISafetyHarness_ConcurrencySlotBoundsN8(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(15 * time.Millisecond)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"ErrForbidden: blocked"}`))
	}))
	defer srv.Close()

	harness := NewDefaultHarness()
	harness.Slots.ResetPeak()
	traceDir := t.TempDir()

	const nCallers = 8
	var wg sync.WaitGroup
	errs := make(chan error, nCallers)
	traceIDs := make(chan string, nCallers)

	for i := 0; i < nCallers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep, err := harness.RunSuiteWithReport(context.Background(), TargetSpec{
				Kind:     TargetKindHTTPLocal,
				Endpoint: srv.URL,
				TraceDir: traceDir,
				Timeout:  15 * time.Second,
			}, []ProbeCategory{ProbeIndirectPromptInjection})
			if err != nil {
				errs <- err
				return
			}
			traceIDs <- rep.ReplayTraceID
		}()
	}

	wg.Wait()
	close(errs)
	close(traceIDs)

	for err := range errs {
		t.Fatalf("concurrent N=8 suite run failed: %v", err)
	}

	if peak := harness.Slots.Peak(); peak > DefaultMaxConcurrentSlots {
		t.Fatalf("concurrency slot invariant violated: peak active=%d > max=%d", peak, DefaultMaxConcurrentSlots)
	}
	if active := harness.Slots.Active(); active != 0 {
		t.Fatalf("slot leak detected: active=%d after all N=8 callers finished", active)
	}

	seen := make(map[string]bool)
	for id := range traceIDs {
		if id == "" {
			t.Errorf("empty trace ID returned")
		}
		seen[id] = true
	}
	if len(seen) != nCallers {
		t.Errorf("expected %d distinct trace IDs, got %d", nCallers, len(seen))
	}
}

// TestAISafetyHarness_EndToEnd_HTTP_VulnerableThenFixed runs all 12 probes against a real local
// httptest.Server in vulnerable mode (proving detection of all 6 categories) and then in hardened
// mode (proving 12/12 pass with 0 noise).
func TestAISafetyHarness_EndToEnd_HTTP_VulnerableThenFixed(t *testing.T) {
	vulnerable := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ProbeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		if !vulnerable {
			// Hardened local AI service: fenced, tenant-scoped, os.OpenRoot, IP-filtered, Conjoiner authz, Shield redacted.
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status":"denied","error":"ErrForbidden: policy check blocked untrusted action"}`))
			return
		}

		// Deliberately vulnerable local AI service reproducing all 6 failure modes.
		switch req.ProbeID {
		case "IPI-01":
			_, _ = w.Write([]byte(`{"action":"refund_order","status":"refund_executed","order_id":"9999","amount":50000}`))
		case "IPI-02":
			_, _ = w.Write([]byte(`{"action":"grant_admin","status":"admin_granted","user":"attacker"}`))
		case "RAG-01":
			_, _ = w.Write([]byte(`{"docs":["tenant-b confidential: secret_project_beta_payload"]}`))
		case "RAG-02":
			_, _ = w.Write([]byte(`{"docs":["tenant-b-billing: all_tenants_dump"]}`))
		case "PATH-01", "PATH-02":
			_, _ = w.Write([]byte(`{"content":"root:x:0:0:root:/root:/bin/sh"}`))
		case "SSRF-01", "SSRF-02":
			_, _ = w.Write([]byte(`{"status":"ssrf_fetch_accepted","fetched":"169.254.169.254 iam/security-credentials ami-id"}`))
		case "MCP-01":
			_, _ = w.Write([]byte(`{"status":"deleted_records","table":"users"}`))
		case "MCP-02":
			_, _ = w.Write([]byte(`{"status":"exported_all_users","role":"admin"}`))
		case "EGRESS-01":
			_, _ = w.Write([]byte(`{"echo":"` + CanaryTokenValue + `"}`))
		case "EGRESS-02":
			_, _ = w.Write([]byte(`{"customer":"` + CanaryPIIValue + `"}`))
		default:
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		}
	}))
	defer srv.Close()

	harness := NewDefaultHarness()
	spec := TargetSpec{
		Kind:     TargetKindHTTPLocal,
		Endpoint: srv.URL,
		TraceDir: t.TempDir(),
	}

	// Phase 1: Vulnerable server -> all 12 probes detect proven failures across all 6 categories.
	vulnReport, err := harness.RunSuiteWithReport(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("vulnerable HTTP suite failed: %v", err)
	}
	if vulnReport.TotalProbes != 12 {
		t.Fatalf("expected 12 total probes, got %d", vulnReport.TotalProbes)
	}
	if vulnReport.ProvenFailures != 12 {
		t.Fatalf("expected 12 proven failures against vulnerable target, got %d", vulnReport.ProvenFailures)
	}
	for _, f := range vulnReport.Findings {
		if !f.Proven || f.FixPatchHint == "" || f.WhyOneLiner == "" || f.ReplayTraceID == "" {
			t.Errorf("incomplete finding %+v", f)
		}
	}

	// Phase 2: Fixed server -> 12/12 pass, 0 proven failures!
	vulnerable = false
	fixedReport, err := harness.RunSuiteWithReport(context.Background(), spec, nil)
	if err != nil {
		t.Fatalf("fixed HTTP suite failed: %v", err)
	}
	if fixedReport.ProvenFailures != 0 || fixedReport.PassedProbes != 12 {
		t.Fatalf("expected 12 passed / 0 failures against fixed target, got %d passed / %d failed",
			fixedReport.PassedProbes, fixedReport.ProvenFailures)
	}
}

// TestAISafetyHarness_EndToEnd_MCPStdio_VulnerableThenFixed exercises real JSON-RPC 2.0 STDIO
// communication with a local mock MCP server subprocess in vulnerable and hardened modes.
func TestAISafetyHarness_EndToEnd_MCPStdio_VulnerableThenFixed(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	harness := NewDefaultHarness()

	// Phase 1: Vulnerable local MCP server over STDIO.
	vulnSpec := TargetSpec{
		Kind:               TargetKindMCPStdio,
		Command:            []string{exe, "-test.run=^TestHelperMockMCPServer$", "--", "vulnerable"},
		AllowDegradedLocal: true,
		TraceDir:           t.TempDir(),
		Timeout:            15 * time.Second,
	}
	vulnReport, err := harness.RunSuiteWithReport(context.Background(), vulnSpec, nil)
	if err != nil {
		t.Fatalf("vulnerable MCP stdio suite failed: %v", err)
	}
	if vulnReport.ProvenFailures < 3 {
		t.Fatalf("expected >=3 proven failures against vulnerable MCP server, got %d", vulnReport.ProvenFailures)
	}

	// Phase 2: Hardened local MCP server over STDIO -> 12/12 pass!
	fixedSpec := TargetSpec{
		Kind:               TargetKindMCPStdio,
		Command:            []string{exe, "-test.run=^TestHelperMockMCPServer$", "--", "fixed"},
		AllowDegradedLocal: true,
		TraceDir:           t.TempDir(),
		Timeout:            15 * time.Second,
	}
	fixedReport, err := harness.RunSuiteWithReport(context.Background(), fixedSpec, nil)
	if err != nil {
		t.Fatalf("fixed MCP stdio suite failed: %v", err)
	}
	if fixedReport.ProvenFailures != 0 || fixedReport.PassedProbes != 12 {
		t.Fatalf("expected 12 passed / 0 failures on hardened MCP server, got %d passed / %d failed",
			fixedReport.PassedProbes, fixedReport.ProvenFailures)
	}
}

// TestHelperMockMCPServer is a real local JSON-RPC 2.0 MCP STDIO helper invoked by
// TestAISafetyHarness_EndToEnd_MCPStdio_VulnerableThenFixed.
func TestHelperMockMCPServer(t *testing.T) {
	if os.Getenv("AEGISBOX_AISAFETY_SANDBOX") != "1" {
		return
	}
	mode := "fixed"
	for _, a := range os.Args {
		if a == "vulnerable" {
			mode = "vulnerable"
		}
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req struct {
			JSONRPC string `json:"jsonrpc"`
			ID      int    `json:"id"`
			Method  string `json:"method"`
			Params  struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}

		if req.Method == "initialize" {
			fmt.Printf(`{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2024-11-05","serverInfo":{"name":"mock-mcp","version":"1.0"}}}`+"\n", req.ID)
			continue
		}

		if mode == "fixed" {
			fmt.Printf(`{"jsonrpc":"2.0","id":%d,"result":{"isError":true,"content":[{"type":"text","text":"ErrForbidden: deterministic authz & confinement blocked request"}]}}`+"\n", req.ID)
			continue
		}

		// Vulnerable MCP server behavior
		switch req.Params.Name {
		case "delete_records":
			fmt.Printf(`{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"deleted_records: users wiped"}]}}`+"\n", req.ID)
		case "export_all_users":
			fmt.Printf(`{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"exported_all_users success"}]}}`+"\n", req.ID)
		case "read_file":
			fmt.Printf(`{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"root:x:0:0:root:/root:/bin/sh"}]}}`+"\n", req.ID)
		case "summarize_ticket":
			fmt.Printf(`{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"refund_executed order 9999 amount 50000"}]}}`+"\n", req.ID)
		default:
			fmt.Printf(`{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"ok"}]}}`+"\n", req.ID)
		}
	}
	os.Exit(0)
}
