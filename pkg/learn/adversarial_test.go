package learn

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKataIsolation_ZeroHostHomeAccess verifies that kata-01-slopsquat and KataWorkspace
// operate strictly inside ephemeral 0700 os.OpenRoot workspaces with an isolated decoy $HOME,
// never touching real host $HOME or ~/.ssh, and blocking traversal/symlink escapes.
func TestKataIsolation_ZeroHostHomeAccess(t *testing.T) {
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	ws, err := NewKataWorkspace("kata-01-slopsquat", "")
	if err != nil {
		t.Fatalf("NewKataWorkspace: %v", err)
	}
	defer ws.Close()

	if strings.HasPrefix(ws.DecoyHome, filepath.Join(realHome, ".ssh")) || ws.DecoyHome == realHome {
		t.Fatalf("SECURITY VIOLATION: DecoyHome %q overlaps real host HOME %q", ws.DecoyHome, realHome)
	}

	// Verify 0700 permissions on kata root directory.
	fi, err := os.Stat(ws.RootDir)
	if err != nil {
		t.Fatalf("stat kata root: %v", err)
	}
	if fi.Mode().Perm() != 0700 {
		t.Errorf("expected kata workspace perms 0700, got %o", fi.Mode().Perm())
	}

	// Verify os.OpenRoot blocks path traversal attempting to read host /etc/passwd or host ~/.ssh.
	if _, err := ws.ReadFile("../../../../etc/passwd"); err == nil {
		t.Fatalf("SECURITY VIOLATION: KataWorkspace allowed path traversal outside os.OpenRoot")
	}
	if _, err := ws.ReadFile(filepath.Join(realHome, ".ssh", "id_rsa")); err == nil {
		t.Fatalf("SECURITY VIOLATION: KataWorkspace allowed absolute host path read")
	}

	// Plant a symlink pointing outside the kata workspace and verify os.OpenRoot refuses to follow it.
	escapeLink := filepath.Join(ws.RootDir, "app", "escape_link")
	if err := os.Symlink("/etc/passwd", escapeLink); err != nil {
		t.Fatalf("create escape symlink: %v", err)
	}
	if _, err := ws.ReadFile("app/escape_link"); err == nil {
		t.Fatalf("SECURITY VIOLATION: os.OpenRoot followed escaping symlink to /etc/passwd")
	}

	// Run kata-01-slopsquat end-to-end and verify decoy HOME isolation + zero host HOME leakage.
	engine := NewEngine()
	traceDir := t.TempDir()
	res, err := engine.RunKata(context.Background(), RunOptions{
		KataID:   "kata-01-slopsquat",
		Check:    false,
		TraceDir: traceDir,
	})
	if err != nil {
		t.Fatalf("RunKata kata-01-slopsquat failed: %v", err)
	}
	if res.DecoyHomeUsed == realHome || strings.HasPrefix(res.DecoyHomeUsed, filepath.Join(realHome, ".ssh")) {
		t.Fatalf("kata used real host HOME %q instead of isolated decoy home", res.DecoyHomeUsed)
	}
	// Verify ephemeral kata workspace was destroyed on exit.
	if _, err := os.Stat(filepath.Dir(res.DecoyHomeUsed)); !os.IsNotExist(err) {
		t.Errorf("expected ephemeral kata workspace to be cleaned up on exit, stat err=%v", err)
	}
}

// TestAllFiveKatas_BreakThenCheckTurnsGreen runs all 5 offline 2-minute security katas
// in break mode (reproducing each attack + saving redacted replay trace) and then --check mode
// (verifying every 5-line fix turns green in <200ms completely offline with zero API keys).
func TestAllFiveKatas_BreakThenCheckTurnsGreen(t *testing.T) {
	engine := NewEngine()
	katas := engine.ListKatas()
	if len(katas) != 5 {
		t.Fatalf("expected 5 katas, got %d", len(katas))
	}

	traceDir := t.TempDir()
	for _, meta := range katas {
		t.Run(meta.ID, func(t *testing.T) {
			// Step 1: Break mode — demonstrate exploit reproducibly offline.
			breakRes, err := engine.RunKata(context.Background(), RunOptions{
				KataID:   meta.ID,
				Check:    false,
				Why:      true,
				TraceDir: traceDir,
			})
			if err != nil {
				t.Fatalf("break mode failed for %s: %v", meta.ID, err)
			}
			if !breakRes.AttackSucceeded {
				t.Errorf("%s break mode expected AttackSucceeded=true", meta.ID)
			}
			if breakRes.ReplayTraceID == "" || breakRes.TracePath == "" {
				t.Errorf("%s break mode missing Flightdeck replay trace", meta.ID)
			}

			// Verify raw decoy private keys & API keys are NEVER written unredacted to trace on disk.
			traceBytes, err := os.ReadFile(breakRes.TracePath)
			if err != nil {
				t.Fatalf("read trace %q: %v", breakRes.TracePath, err)
			}
			traceStr := string(traceBytes)
			if strings.Contains(traceStr, DecoyOpenAIKey) || strings.Contains(traceStr, "AEGISBOX_KATA_DECOY_KEY_NOT_REAL") {
				t.Errorf("SECURITY VIOLATION: raw decoy secret leaked unredacted into trace for %s", meta.ID)
			}

			// Step 2: Check mode (--check) — apply 5-line fix and verify green check!
			checkRes, err := engine.RunKata(context.Background(), RunOptions{
				KataID:   meta.ID,
				Check:    true,
				Why:      true,
				TraceDir: traceDir,
			})
			if err != nil {
				t.Fatalf("check mode failed for %s: %v", meta.ID, err)
			}
			if !checkRes.Passed || checkRes.AttackSucceeded {
				t.Errorf("%s --check expected Passed=true & AttackSucceeded=false, got Passed=%v AttackSucceeded=%v (%s)",
					meta.ID, checkRes.Passed, checkRes.AttackSucceeded, checkRes.ObservedEffect)
			}

			formatted := FormatKataResult(checkRes, true)
			if !strings.Contains(formatted, "✓ PASS") || !strings.Contains(formatted, "Deep:") {
				t.Errorf("unexpected calm UB-CLI-v2 output for %s:\n%s", meta.ID, formatted)
			}
		})
	}
}

func TestKataListAndJSONFormatting(t *testing.T) {
	engine := NewEngine()
	katas := engine.ListKatas()

	listOut := FormatKataList(katas)
	for _, id := range []string{
		"kata-01-slopsquat",
		"kata-02-dotenv-leak",
		"kata-03-rag-injection",
		"kata-04-mcp-overprivilege",
		"kata-05-egress-leak",
	} {
		if !strings.Contains(listOut, id) {
			t.Errorf("FormatKataList missing %s", id)
		}
	}

	rawJSON, err := FormatKataJSON(katas)
	if err != nil {
		t.Fatalf("FormatKataJSON: %v", err)
	}
	if !strings.Contains(string(rawJSON), "kata-03-rag-injection") {
		t.Errorf("JSON output missing kata-03-rag-injection")
	}
}
