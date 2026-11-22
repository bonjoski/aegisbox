package learn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportAndWorkspaceCheck_SymlinkAndTraversalRejected(t *testing.T) {
	engine := NewEngine()
	base := t.TempDir()

	// 1. Path traversal in --export-dir and --workspace MUST fail closed.
	for _, badPath := range []string{"", "   ", "../escaped-kata", base + "/../escaped", "foo\x00bar"} {
		if _, err := engine.ExportKata("kata-03-rag-injection", badPath); !errors.Is(err, ErrWorkspacePathTraversal) {
			t.Errorf("ExportKata(%q) expected ErrWorkspacePathTraversal, got: %v", badPath, err)
		}
		if _, err := engine.EvaluateWorkspace(context.Background(), RunOptions{
			KataID:       "kata-03-rag-injection",
			WorkspaceDir: badPath,
			Check:        true,
			TraceDir:     t.TempDir(),
		}); !errors.Is(err, ErrWorkspacePathTraversal) {
			t.Errorf("EvaluateWorkspace(%q) expected ErrWorkspacePathTraversal, got: %v", badPath, err)
		}
	}

	// 2. Symlinked export directory MUST fail closed with ErrWorkspaceSymlink.
	realDir := filepath.Join(base, "real-dir")
	if err := os.MkdirAll(realDir, 0700); err != nil {
		t.Fatal(err)
	}
	symDir := filepath.Join(base, "sym-dir")
	if err := os.Symlink(realDir, symDir); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ExportKata("kata-03-rag-injection", symDir); !errors.Is(err, ErrWorkspaceSymlink) {
		t.Fatalf("expected ErrWorkspaceSymlink for symlinked export-dir, got: %v", err)
	}
	if _, err := engine.EvaluateWorkspace(context.Background(), RunOptions{
		KataID:       "kata-03-rag-injection",
		WorkspaceDir: symDir,
		Check:        true,
		TraceDir:     t.TempDir(),
	}); !errors.Is(err, ErrWorkspaceSymlink) {
		t.Fatalf("expected ErrWorkspaceSymlink for symlinked workspace, got: %v", err)
	}

	// 3. Symlinked handler.go inside a legitimate exported workspace MUST fail closed!
	validDir := filepath.Join(base, "kata03-sym-handler")
	if _, err := engine.ExportKata("kata-03-rag-injection", validDir); err != nil {
		t.Fatalf("ExportKata failed: %v", err)
	}
	handlerPath := filepath.Join(validDir, ExportedHandlerFilename)
	if err := os.Remove(handlerPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", handlerPath); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.EvaluateWorkspace(context.Background(), RunOptions{
		KataID:       "kata-03-rag-injection",
		WorkspaceDir: validDir,
		Check:        true,
		TraceDir:     t.TempDir(),
	}); !errors.Is(err, ErrWorkspaceSymlink) {
		t.Fatalf("expected ErrWorkspaceSymlink when handler.go is a symlink, got: %v", err)
	}

	// 4. Oversized (> 256KB) handler.go MUST fail closed with ErrWorkspaceFileTooLarge.
	oversizedDir := filepath.Join(base, "kata03-oversized")
	if _, err := engine.ExportKata("kata-03-rag-injection", oversizedDir); err != nil {
		t.Fatalf("ExportKata oversized dir failed: %v", err)
	}
	hugeHandler := "package kata03\n// " + strings.Repeat("X", MaxWorkspaceHandlerBytes+1024) + "\n"
	if err := os.WriteFile(filepath.Join(oversizedDir, ExportedHandlerFilename), []byte(hugeHandler), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.EvaluateWorkspace(context.Background(), RunOptions{
		KataID:       "kata-03-rag-injection",
		WorkspaceDir: oversizedDir,
		Check:        true,
		TraceDir:     t.TempDir(),
	}); !errors.Is(err, ErrWorkspaceFileTooLarge) {
		t.Fatalf("expected ErrWorkspaceFileTooLarge for >256KB handler.go, got: %v", err)
	}
}

// TestExportKata03_UnpatchedFails_CommentSpoofFails_PatchedTurnsGreen verifies the full
// hands-on developer loop: export kata-03-rag-injection -> --check fails on unpatched workspace ->
// comment-only spoof still fails -> apply 5-line XML delimiter fence + taint gate -> --check turns GREEN!
func TestExportKata03_UnpatchedFails_CommentSpoofFails_PatchedTurnsGreen(t *testing.T) {
	engine := NewEngine()
	exportDir := filepath.Join(t.TempDir(), "kata03-lab")
	traceDir := t.TempDir()

	// Step 1: Export editable 0700 workspace.
	exp, err := engine.ExportKata("kata-03-rag-injection", exportDir)
	if err != nil {
		t.Fatalf("ExportKata failed: %v", err)
	}
	fi, err := os.Stat(exp.Dir)
	if err != nil {
		t.Fatalf("stat exported dir: %v", err)
	}
	if fi.Mode().Perm() != 0700 {
		t.Errorf("expected 0700 permissions on exported workspace, got %o", fi.Mode().Perm())
	}
	for _, f := range []string{ExportedHandlerFilename, "README.md", ExportedManifestFilename} {
		if _, err := os.Stat(filepath.Join(exp.Dir, f)); err != nil {
			t.Errorf("expected exported file %q to exist: %v", f, err)
		}
	}

	// Step 2: --check on unpatched workspace MUST FAIL with calm Fix-Forward guidance.
	unpatchedRes, err := engine.RunKata(context.Background(), RunOptions{
		KataID:       "kata-03-rag-injection",
		WorkspaceDir: exportDir,
		Check:        true,
		TraceDir:     traceDir,
	})
	if err != nil {
		t.Fatalf("RunKata unpatched check returned unexpected error: %v", err)
	}
	if unpatchedRes.Passed || !unpatchedRes.AttackSucceeded {
		t.Fatalf("expected unpatched workspace to FAIL check, got Passed=%v AttackSucceeded=%v", unpatchedRes.Passed, unpatchedRes.AttackSucceeded)
	}
	formattedFail := FormatKataResult(unpatchedRes, false)
	if !strings.Contains(formattedFail, "✗ CHECK FAILED") || !strings.Contains(formattedFail, "Fix:") {
		t.Fatalf("expected calm UB-CLI-v2 Fix-Forward output on failed check, got:\n%s", formattedFail)
	}

	// Step 3: Adversarial bypass check — putting XML fence only inside comments MUST STILL FAIL!
	commentSpoof := `package kata03

import "fmt"

// safeTicket := strings.ReplaceAll(ticket, "</untrusted_artifact>", "&lt;/untrusted_artifact&gt;")
// <untrusted_artifact source="rag_ticket"> </untrusted_artifact>
func BuildSupportPrompt(ticket string) string {
	return fmt.Sprintf("Summarize ticket:\n%s", ticket)
}

func AuthorizeToolCall(toolName string, hasUntrustedRAGInput bool) error {
	// if toolName == "refund_order" && hasUntrustedRAGInput { return ErrTaintedToolBlocked }
	return nil
}
`
	if err := os.WriteFile(exp.HandlerFile, []byte(commentSpoof), 0600); err != nil {
		t.Fatal(err)
	}
	spoofRes, err := engine.RunKata(context.Background(), RunOptions{
		KataID:       "kata-03-rag-injection",
		WorkspaceDir: exportDir,
		Check:        true,
		TraceDir:     traceDir,
	})
	if err != nil {
		t.Fatalf("RunKata comment spoof check error: %v", err)
	}
	if spoofRes.Passed {
		t.Fatalf("SECURITY VIOLATION: comment-only XML fence bypassed workspace evaluator!")
	}

	// Step 4: Apply the real 5-line Stormcage XML delimiter fence + taint gate fix!
	patchedHandler := `package kata03

import (
	"errors"
	"fmt"
	"strings"
)

var ErrTaintedToolBlocked = errors.New("tainted mutating tool blocked")

func BuildSupportPrompt(ticket string) string {
	safeTicket := strings.ReplaceAll(ticket, "</untrusted_artifact>", "&lt;/untrusted_artifact&gt;")
	return fmt.Sprintf("Summarize ticket:\n<untrusted_artifact source=\"rag_ticket\">\n%s\n</untrusted_artifact>", safeTicket)
}

func AuthorizeToolCall(toolName string, hasUntrustedRAGInput bool) error {
	if toolName == "refund_order" && hasUntrustedRAGInput {
		return ErrTaintedToolBlocked
	}
	return nil
}
`
	if err := os.WriteFile(exp.HandlerFile, []byte(patchedHandler), 0600); err != nil {
		t.Fatal(err)
	}

	// Step 5: Re-run --check -> MUST TURN GREEN!
	greenRes, err := engine.RunKata(context.Background(), RunOptions{
		KataID:       "kata-03-rag-injection",
		WorkspaceDir: exportDir,
		Check:        true,
		Why:          true,
		TraceDir:     traceDir,
	})
	if err != nil {
		t.Fatalf("RunKata patched check failed: %v", err)
	}
	if !greenRes.Passed || greenRes.AttackSucceeded {
		t.Fatalf("expected patched workspace to turn GREEN, got Passed=%v AttackSucceeded=%v (%s)",
			greenRes.Passed, greenRes.AttackSucceeded, greenRes.ObservedEffect)
	}
	formattedPass := FormatKataResult(greenRes, true)
	if !strings.Contains(formattedPass, "✓ PASS") {
		t.Fatalf("expected calm ✓ PASS output, got:\n%s", formattedPass)
	}
}

func TestExportAllFiveKatas_UnpatchedFails(t *testing.T) {
	engine := NewEngine()
	for _, meta := range engine.ListKatas() {
		t.Run(meta.ID, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), meta.ID)
			if _, err := engine.ExportKata(meta.ID, dir); err != nil {
				t.Fatalf("ExportKata(%s): %v", meta.ID, err)
			}
			res, err := engine.RunKata(context.Background(), RunOptions{
				KataID:       meta.ID,
				WorkspaceDir: dir,
				Check:        true,
				TraceDir:     t.TempDir(),
			})
			if err != nil {
				t.Fatalf("RunKata(%s) unpatched error: %v", meta.ID, err)
			}
			if res.Passed {
				t.Fatalf("expected unpatched exported %s to fail --check", meta.ID)
			}
		})
	}
}
