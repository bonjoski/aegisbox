package vmm_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/aegisbox/pkg/vmm"
)

func TestSeatbeltProfile_GenerationAndDenials(t *testing.T) {
	tempWS, err := os.MkdirTemp("", "aegisbox-sb-test-*")
	if err != nil {
		t.Fatalf("failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(tempWS)

	profile := vmm.GenerateSeatbeltProfile(tempWS)
	if profile == "" && vmm.HasSeatbelt() {
		t.Fatalf("expected non-empty seatbelt profile on macOS")
	}

	if vmm.HasSeatbelt() {
		if !strings.Contains(profile, "deny process-info*") {
			t.Errorf("expected seatbelt profile to deny process-info*")
		}
		if !strings.Contains(profile, ".ssh") {
			t.Errorf("expected seatbelt profile to deny .ssh")
		}
		if !strings.Contains(profile, ".aws") {
			t.Errorf("expected seatbelt profile to deny .aws")
		}
		if !strings.Contains(profile, "/tmp/cc-socks") {
			t.Errorf("expected seatbelt profile to deny /tmp/cc-socks")
		}
		if !strings.Contains(profile, `(deny file-write* (subpath "/tmp"))`) {
			t.Errorf("expected seatbelt profile to deny file-write* to /tmp")
		}
		if !strings.Contains(profile, tempWS) {
			t.Errorf("expected seatbelt profile to allow writing to tempWS")
		}
	}
}

func TestSeatbelt_ExecutionContainment(t *testing.T) {
	if !vmm.HasSeatbelt() {
		t.Skip("sandbox-exec not available, skipping live Seatbelt test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tempWS, err := os.MkdirTemp("", "aegisbox-sb-run-*")
	if err != nil {
		t.Fatalf("failed to create temp ws: %v", err)
	}
	defer os.RemoveAll(tempWS)

	// 1. Verify writes inside workspaceMount succeed
	writeInside := "echo 'allowed payload' > inside.txt"
	cmdInside := vmm.WrapCommandWithSeatbelt(ctx, writeInside, tempWS)
	cmdInside.Dir = tempWS
	if err := cmdInside.Run(); err != nil {
		t.Fatalf("expected write inside shadow workspace to succeed under Seatbelt: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(tempWS, "inside.txt"))
	if err != nil || strings.TrimSpace(string(content)) != "allowed payload" {
		t.Fatalf("failed to verify file written inside workspace: %v", err)
	}

	home, err := os.UserHomeDir()
	if err == nil {
		// 2. Verify writes to host home directory are blocked by Seatbelt
		hostEscapePath := filepath.Join(home, "aegisbox_sb_escape_test.txt")
		_ = os.Remove(hostEscapePath)

		writeOutside := "echo 'escape payload' > " + hostEscapePath
		cmdOutside := vmm.WrapCommandWithSeatbelt(ctx, writeOutside, tempWS)
		cmdOutside.Dir = tempWS

		out, err := cmdOutside.CombinedOutput()
		_ = os.Remove(hostEscapePath)

		if err == nil {
			t.Fatalf("SECURITY VIOLATION: Seatbelt failed to block writing to host home directory! Out: %s", string(out))
		}

		// 3. Verify reads to sensitive files in host home directory are blocked by Seatbelt
		readHome := "cat " + filepath.Join(home, ".bash_history")
		cmdReadHome := vmm.WrapCommandWithSeatbelt(ctx, readHome, tempWS)
		cmdReadHome.Dir = tempWS
		if err := cmdReadHome.Run(); err == nil {
			t.Fatalf("SECURITY VIOLATION: Seatbelt failed to block reading host dotfiles!")
		}
	}

	// 4. Verify writes to host /tmp outside workspaceMount are blocked
	writeTmpOutside := "echo 'tmp escape' > /tmp/aegisbox_tmp_escape_test.txt"
	cmdTmp := vmm.WrapCommandWithSeatbelt(ctx, writeTmpOutside, tempWS)
	cmdTmp.Dir = tempWS
	outTmp, errTmp := cmdTmp.CombinedOutput()
	_ = os.Remove("/tmp/aegisbox_tmp_escape_test.txt")
	if errTmp == nil {
		t.Fatalf("SECURITY VIOLATION: Seatbelt failed to block writing to /tmp outside workspace! Out: %s", string(outTmp))
	}

	// 5. Verify process table inspection is blocked (ps aux)
	procInspect := "ps aux"
	cmdProc := vmm.WrapCommandWithSeatbelt(ctx, procInspect, tempWS)
	cmdProc.Dir = tempWS
	outProc, errProc := cmdProc.CombinedOutput()
	if errProc == nil && len(outProc) > 0 {
		t.Fatalf("SECURITY VIOLATION: Seatbelt failed to deny process inspection! Out: %s", string(outProc))
	}
}
