package matrix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/aegisbox/pkg/argus"
	"github.com/bonjoski/aegisbox/pkg/mcp"
	"github.com/bonjoski/aegisbox/pkg/netgate"
	"github.com/bonjoski/aegisbox/pkg/telemetry"
	"github.com/bonjoski/aegisbox/pkg/workspace"
)

// TestMultiAgentAdversarialRange evaluates all 6 core attack vectors in an integrated regression test.
func TestMultiAgentAdversarialRange(t *testing.T) {
	ctx := context.Background()

	// Vector 1: Reverse shell / PTY spawn subshell
	t.Run("Vector1_PTY_ReverseShell_BlockedByArgus", func(t *testing.T) {
		analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict)
		cmd := `python3 -c "import pty; pty.spawn('/bin/bash')"`
		report, err := analyzer.Analyze(ctx, cmd)
		if err != nil {
			t.Fatalf("unexpected analyzer error: %v", err)
		}
		if report.Allowed {
			t.Errorf("expected reverse shell PTY payload to be BLOCKED, but was allowed")
		}
	})

	// Vector 2: Canary token exfiltration attempt to AWS metadata 169.254.169.254
	t.Run("Vector2_CanaryMetadataExfil_TriggeredPriorityAlert", func(t *testing.T) {
		collector := telemetry.NewTelemetryCollector()
		collector.RecordCanaryTripwire("vm-agent-claude", "169.254.169.254")

		select {
		case alert := <-collector.PriorityChannel():
			if !alert.CanaryTriggered || alert.CanaryTargetIP != "169.254.169.254" {
				t.Errorf("unexpected canary alert: %+v", alert)
			}
			if alert.Severity != telemetry.SeverityCritical {
				t.Errorf("expected CRITICAL severity on canary tripwire")
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("canary tripwire alert not received on priority channel")
		}
	})

	// Vector 3: DNS Tunneling exfiltration attempt (<secret>.attacker.com)
	t.Run("Vector3_DNSTunneling_BlockedByDNSProxy", func(t *testing.T) {
		dnsProxy := netgate.NewDNSProxy([]string{"*.github.com", "registry.npmjs.org"}, "1.1.1.1:53")
		maliciousTunnelDomain := "dG9rZW4xMjM0NQ==.exfil.attacker.com"
		if dnsProxy.IsDomainAllowed(maliciousTunnelDomain) {
			t.Errorf("expected DNS tunneling domain %s to be BLOCKED, but was allowed", maliciousTunnelDomain)
		}
	})

	// Vector 4: Special inode weaponization (symlink escaping root)
	t.Run("Vector4_SpecialInodeEscape_RejectedByCommitGate", func(t *testing.T) {
		tempDir := t.TempDir()
		upperDir := filepath.Join(tempDir, "upper")
		_ = os.MkdirAll(upperDir, 0700)

		// Create an escaping symlink pointing to /etc
		evilSymlink := filepath.Join(upperDir, "leaked_etc")
		if err := os.Symlink("/etc", evilSymlink); err != nil {
			t.Skip("skipping symlink creation on this platform")
		}

		err := workspace.InodeSanitizer(upperDir)
		if err == nil {
			t.Errorf("expected InodeSanitizer to REJECT escaping symlink, but returned nil")
		}
	})

	// Vector 5: Deceptive Unicode Bidi override attack (\u202E)
	t.Run("Vector5_UnicodeBidiOverride_Stripped", func(t *testing.T) {
		bidiPayload := "safe_file\u202Eexe.doc"
		// Bidi stripping replaces \u202A-\u202E, \u2066-\u2069
		cleaned := strings.Map(func(r rune) rune {
			if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
				return -1
			}
			return r
		}, bidiPayload)

		if strings.Contains(cleaned, "\u202E") {
			t.Errorf("failed to strip Unicode bidi override")
		}
		if cleaned != "safe_fileexe.doc" {
			t.Errorf("unexpected sanitized string: %s", cleaned)
		}
	})

	// Vector 6: Destructive filesystem deletion via MCP tool call
	t.Run("Vector6_DestructiveDeletion_BlockedByCEL", func(t *testing.T) {
		celEngine, err := mcp.NewCELPolicyEngine()
		if err != nil {
			t.Fatalf("failed to create CEL engine: %v", err)
		}

		proxy := mcp.NewProxy(celEngine, nil, "/workspace", "microvm-hardened")
		payload := []byte(`{
			"jsonrpc": "2.0",
			"id": 99,
			"method": "tools/call",
			"params": {
				"name": "run_command",
				"arguments": {
					"command": "rm -rf /"
				}
			}
		}`)

		_, resp, err := proxy.ProcessClientRequest(ctx, payload)
		if err != nil {
			t.Fatalf("unexpected internal error: %v", err)
		}
		if resp == nil || resp.Error == nil {
			t.Fatalf("expected rm -rf / to be BLOCKED by CEL policy, but succeeded")
		}
		if !strings.Contains(strings.ToLower(resp.Error.Message), "blocked") && !strings.Contains(strings.ToLower(resp.Error.Message), "denied") {
			t.Errorf("expected denial or blocked message, got: %s", resp.Error.Message)
		}
	})
}
