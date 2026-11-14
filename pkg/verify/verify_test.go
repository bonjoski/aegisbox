package verify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleSARIF = `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SnykSecurityScanner",
          "rules": [
            {
              "id": "RULE-SSRF-01",
              "name": "ServerSideRequestForgery",
              "properties": {
                "tags": ["CWE-918", "security"]
              },
              "defaultConfiguration": {
                "level": "error"
              }
            },
            {
              "id": "RULE-SQLI-01",
              "name": "SQLInjection",
              "properties": {
                "tags": ["CWE-89", "security"]
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "RULE-SSRF-01",
          "level": "error",
          "message": {
            "text": "Unvalidated HTTP request allows SSRF"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "client.go"
                },
                "region": {
                  "startLine": 42
                }
              }
            }
          ]
        }
      ]
    }
  ]
}`

func TestParseSARIF(t *testing.T) {
	findings, err := ParseSARIF(strings.NewReader(sampleSARIF))
	if err != nil {
		t.Fatalf("ParseSARIF failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.RuleID != "RULE-SSRF-01" {
		t.Errorf("expected rule ID RULE-SSRF-01, got %s", f.RuleID)
	}
	if f.CWE != 918 {
		t.Errorf("expected CWE-918, got %d", f.CWE)
	}
	if f.FilePath != "client.go" {
		t.Errorf("expected client.go, got %s", f.FilePath)
	}
	if f.StartLine != 42 {
		t.Errorf("expected start line 42, got %d", f.StartLine)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", f.Severity)
	}
}

func TestVerifyFinding_ExploitableSSRF(t *testing.T) {
	tmpDir := t.TempDir()

	// Vulnerable client code
	vulnerableCode := `package main
import "net/http"
func fetchUpstream(url string) (*http.Response, error) {
    return http.Get(url)
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "client.go"), []byte(vulnerableCode), 0644); err != nil {
		t.Fatal(err)
	}

	pipeline := NewVerificationPipeline(2, 5*time.Second, false)
	finding := Finding{
		RuleID:    "RULE-SSRF-01",
		CWE:       918,
		FilePath:  "client.go",
		StartLine: 4,
		Severity:  SeverityHigh,
	}

	res, err := pipeline.VerifyFinding(context.Background(), tmpDir, finding)
	if err != nil {
		t.Fatalf("VerifyFinding failed: %v", err)
	}

	if res.Verdict != VerdictExploitable {
		t.Errorf("expected VerdictExploitable, got %s", res.Verdict)
	}
	if !strings.Contains(res.PayloadTrace, "169.254.169.254") {
		t.Errorf("expected payload trace with IMDS, got: %s", res.PayloadTrace)
	}
}

func TestVerifyFinding_CleanMitigatedCode(t *testing.T) {
	tmpDir := t.TempDir()

	// Mitigated code with EgressGuard
	cleanCode := `package main
import "github.com/bonjoski/conjoiner/pkg/mcp/guard"
func fetchUpstream(url string) (*http.Response, error) {
    client := guard.NewClient()
    return client.Get(url)
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "client.go"), []byte(cleanCode), 0644); err != nil {
		t.Fatal(err)
	}

	pipeline := NewVerificationPipeline(2, 5*time.Second, false)
	finding := Finding{
		RuleID:    "RULE-SSRF-01",
		CWE:       918,
		FilePath:  "client.go",
		StartLine: 4,
	}

	res, err := pipeline.VerifyFinding(context.Background(), tmpDir, finding)
	if err != nil {
		t.Fatalf("VerifyFinding failed: %v", err)
	}

	if res.Verdict != VerdictFalsePositive {
		t.Errorf("expected VerdictFalsePositive for mitigated code, got %s", res.Verdict)
	}
}
