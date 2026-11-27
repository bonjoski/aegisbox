package benchmark

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSirenSuite_Full12ClassDifferentialPass(t *testing.T) {
	catalog := DefaultSirenCatalog()
	if len(catalog) != 12 {
		t.Fatalf("expected 12 Siren misconfiguration classes, got %d", len(catalog))
	}

	expectedIDs := []string{
		"SIREN-01", "SIREN-02", "SIREN-03", "SIREN-04",
		"SIREN-05", "SIREN-06", "SIREN-07", "SIREN-08",
		"SIREN-09", "SIREN-10", "SIREN-11", "SIREN-12",
	}
	for i, want := range expectedIDs {
		if catalog[i].ID != want {
			t.Fatalf("catalog[%d].ID = %q, want %q", i, catalog[i].ID, want)
		}
		if catalog[i].Mutate == nil || catalog[i].Probe == nil {
			t.Fatalf("catalog[%d] (%s) has nil Mutate or Probe", i, want)
		}
	}

	report, err := RunSirenSuite(context.Background(), SirenSuiteConfig{
		Concurrency:     4,
		PerProbeTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("RunSirenSuite failed: %v", err)
	}
	if !report.Passed {
		t.Fatalf("expected Siren differential suite to pass 12/12, failed=%d:\n%s", report.FailedProbes, report.FormatScorecard())
	}
	if report.TotalProbes != 12 || report.PassedProbes != 12 || report.WeakenedEscaped != 12 || report.HardenedBlocked != 12 {
		t.Fatalf("unexpected scorecard counts: total=%d passed=%d weakEsc=%d hardBlk=%d",
			report.TotalProbes, report.PassedProbes, report.WeakenedEscaped, report.HardenedBlocked)
	}

	// Verify JSON scorecard round-trip and terminal rendering.
	raw, err := report.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}
	var parsed SirenBenchmarkReport
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if parsed.SchemaVersion != SirenSchemaVersion || !parsed.Passed || len(parsed.Results) != 12 {
		t.Fatalf("unexpected unmarshaled report: %+v", parsed)
	}

	sc := report.FormatScorecard()
	if !strings.Contains(sc, "SIREN-01") || !strings.Contains(sc, "SIREN-12") || !strings.Contains(sc, "FINAL VERDICT: PASS") {
		t.Fatalf("scorecard missing expected sections:\n%s", sc)
	}
}

// TestSirenAdversarial_FailsWhenWeakenedProbeDoesNotEscape verifies the core differential
// invariant: an ineffective probe that fails to escape the weakened sandbox MUST fail the suite.
func TestSirenAdversarial_FailsWhenWeakenedProbeDoesNotEscape(t *testing.T) {
	brokenCatalog := []SirenMutation{
		{
			ID:       "SIREN-BROKEN-WEAK",
			Name:     "Broken No-Op Mutation",
			Category: "read_only_escape",
			Mutate: func(p *AirlockProfileSpec) error {
				// Deliberately fail to weaken the profile (no-op).
				return nil
			},
			Probe: probeSIREN01ReadOnlySSHKey,
		},
	}

	report, err := RunSirenSuite(context.Background(), SirenSuiteConfig{
		Concurrency:     2,
		PerProbeTimeout: 2 * time.Second,
		Mutations:       brokenCatalog,
	})
	if err != nil {
		t.Fatalf("RunSirenSuite returned unexpected error: %v", err)
	}
	if report.Passed {
		t.Fatalf("FAIL-OPEN: suite passed even though weakened probe never escaped!")
	}
	if report.FailedProbes != 1 || report.Results[0].WeakenedEscaped {
		t.Fatalf("expected WeakenedEscaped=false and FailedProbes=1, got %+v", report.Results[0])
	}
	if report.Results[0].Status != "FAIL_WEAKENED_NO_ESCAPE" {
		t.Fatalf("expected status FAIL_WEAKENED_NO_ESCAPE, got %q", report.Results[0].Status)
	}
}

// TestSirenAdversarial_FailsWhenHardenedSandboxLeaks verifies that a real misconfiguration
// in the base hardened profile (e.g., omitting ~/.ssh read deny) is caught immediately.
func TestSirenAdversarial_FailsWhenHardenedSandboxLeaks(t *testing.T) {
	report, err := RunSirenSuite(context.Background(), SirenSuiteConfig{
		Concurrency:     4,
		PerProbeTimeout: 5 * time.Second,
		BaseProfile: func(canary *CanaryRoot) *AirlockProfileSpec {
			p := HardenedAirlockProfile(canary)
			// Simulate production regression: read-only SSH credential boundary dropped.
			p.DenySSHRead = false
			return p
		},
	})
	if err != nil {
		t.Fatalf("RunSirenSuite returned unexpected error: %v", err)
	}
	if report.Passed {
		t.Fatalf("FAIL-OPEN: suite passed despite hardened profile leaking SIREN-01 SSH key!")
	}

	foundLeak := false
	for _, r := range report.Results {
		if r.ID == "SIREN-01" {
			foundLeak = true
			if r.HardenedBlocked || r.Passed || r.Status != "FAIL_HARDENED_LEAK" {
				t.Fatalf("expected SIREN-01 to report FAIL_HARDENED_LEAK, got %+v", r)
			}
		}
	}
	if !foundLeak {
		t.Fatal("SIREN-01 result missing from report")
	}
}

// TestSirenAdversarial_CanaryIsolationZeroRealHomeAccess asserts that CanaryRoot creates
// strictly 0700 isolated dirs outside os.UserHomeDir() and removes all files on Cleanup().
func TestSirenAdversarial_CanaryIsolationZeroRealHomeAccess(t *testing.T) {
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}

	canary, err := NewCanaryRoot()
	if err != nil {
		t.Fatalf("NewCanaryRoot: %v", err)
	}

	info, err := os.Stat(canary.BaseDir)
	if err != nil {
		t.Fatalf("stat canary BaseDir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("expected canary BaseDir mode 0700, got %o", perm)
	}

	// Verify no canary path resides under real $HOME.
	cleanHome := filepath.Clean(realHome)
	for _, p := range []string{canary.BaseDir, canary.HomeDir, canary.SSHKeyPath, canary.AuthorizedKeysPath, canary.AWSCredPath, canary.SocketPath, canary.WorktreeDir} {
		cleanP := filepath.Clean(p)
		if cleanP == cleanHome || strings.HasPrefix(cleanP, cleanHome+string(filepath.Separator)) {
			t.Fatalf("CANARY ESCAPE: path %q overlaps real home %q", cleanP, cleanHome)
		}
	}

	// Verify ValidateIsolation fails closed if BaseDir is tampered to point inside real $HOME.
	tampered := &CanaryRoot{
		BaseDir:    filepath.Join(cleanHome, ".ssh"),
		HomeDir:    cleanHome,
		SSHKeyPath: filepath.Join(cleanHome, ".ssh", "id_ed25519"),
	}
	if err := tampered.ValidateIsolation(); err == nil {
		t.Fatal("FAIL-OPEN: ValidateIsolation accepted a path inside real $HOME")
	}

	baseDir := canary.BaseDir
	if err := canary.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if _, err := os.Stat(baseDir); !os.IsNotExist(err) {
		t.Fatalf("canary directory %q still exists after Cleanup()", baseDir)
	}
}

// TestSirenAdversarial_BoundedConcurrencyAndTimeout probes the FIFO semaphore ceiling
// and ensures hung probes fail closed at PerProbeTimeout.
func TestSirenAdversarial_BoundedConcurrencyAndTimeout(t *testing.T) {
	const maxAllowed = 3
	var current atomic.Int64
	var highWater atomic.Int64

	report, err := RunSirenSuite(context.Background(), SirenSuiteConfig{
		Concurrency:     maxAllowed,
		PerProbeTimeout: 5 * time.Second,
		OnWorkerStart: func() {
			n := current.Add(1)
			for {
				prev := highWater.Load()
				if n <= prev || highWater.CompareAndSwap(prev, n) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
		},
		OnWorkerEnd: func() {
			current.Add(-1)
		},
	})
	if err != nil {
		t.Fatalf("RunSirenSuite failed: %v", err)
	}
	if !report.Passed {
		t.Fatalf("expected pass under bounded concurrency, got %+v", report)
	}
	if got := highWater.Load(); got > maxAllowed {
		t.Fatalf("CONCURRENCY BREACH: observed %d active workers, ceiling was %d", got, maxAllowed)
	}

	// Timeout test: hung probe must fail closed without deadlocking.
	hungCatalog := []SirenMutation{
		{
			ID:       "SIREN-HANG",
			Name:     "Simulated Hung Probe",
			Category: "dos",
			Mutate:   func(p *AirlockProfileSpec) error { return nil },
			Probe: func(ctx context.Context, canary *CanaryRoot, profilePath string) ProbeOutcome {
				<-ctx.Done()
				return ProbeOutcome{Err: ctx.Err(), Evidence: "timed out"}
			},
		},
	}
	timeoutReport, err := RunSirenSuite(context.Background(), SirenSuiteConfig{
		Concurrency:     2,
		PerProbeTimeout: 60 * time.Millisecond,
		Mutations:       hungCatalog,
	})
	if err != nil {
		t.Fatalf("RunSirenSuite returned error on timeout: %v", err)
	}
	if timeoutReport.Passed || timeoutReport.Results[0].Status != "FAIL_TIMEOUT" {
		t.Fatalf("expected FAIL_TIMEOUT on hung probe, got passed=%v status=%q", timeoutReport.Passed, timeoutReport.Results[0].Status)
	}
}

// TestSirenAdversarial_N8ParallelSuitesUnderRace stress-tests N=8 concurrent Siren differential
// suite invocations simultaneously to verify zero cross-worktree interference or data races.
func TestSirenAdversarial_N8ParallelSuitesUnderRace(t *testing.T) {
	const parallelAgents = 8
	var wg sync.WaitGroup
	errCh := make(chan error, parallelAgents)

	for i := 0; i < parallelAgents; i++ {
		wg.Add(1)
		go func(agentIdx int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			report, err := RunSirenSuite(ctx, SirenSuiteConfig{
				Concurrency:     4,
				PerProbeTimeout: 5 * time.Second,
			})
			if err != nil {
				errCh <- err
				return
			}
			if !report.Passed || report.PassedProbes != 12 {
				errCh <- os.ErrInvalid
			}
		}(i)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("N=8 parallel Siren suite failed: %v", err)
	}
}
