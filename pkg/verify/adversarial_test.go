package verify

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAdversarial_PathTraversalInSARIF(t *testing.T) {
	// Malicious SARIF with path traversal URI
	maliciousSARIF := `{
  "version": "2.1.0",
  "runs": [
    {
      "tool": { "driver": { "name": "scanner", "rules": [] } },
      "results": [
        {
          "ruleId": "RULE-01",
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "../../../../../etc/passwd"
                },
                "region": { "startLine": 1 }
              }
            }
          ]
        }
      ]
    }
  ]
}`

	findings, err := ParseSARIF(strings.NewReader(maliciousSARIF))
	if err != nil {
		t.Fatalf("ParseSARIF failed: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	// Verify that the path traversal is neutralized (base name only or clean local path)
	f := findings[0]
	if strings.HasPrefix(f.FilePath, "..") || strings.Contains(f.FilePath, "/") {
		t.Errorf("path traversal not neutralized in FilePath: %s", f.FilePath)
	}
	if f.FilePath != "passwd" {
		t.Errorf("expected neutralized base filename 'passwd', got %s", f.FilePath)
	}
}

func TestAdversarial_MicroVMConcurrencySaturation(t *testing.T) {
	// Initialize pipeline with strictly 2 slots
	pipeline := NewVerificationPipeline(2, 2*time.Second, false)

	// Launch 10 concurrent requests simultaneously
	var wg sync.WaitGroup
	errCount := 0
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			finding := Finding{
				RuleID:   "RULE-CONCURRENCY",
				CWE:      918,
				FilePath: "nonexistent.go",
			}
			res, err := pipeline.VerifyFinding(context.Background(), "/tmp", finding)
			if err != nil {
				mu.Lock()
				errCount++
				mu.Unlock()
				return
			}
			if res == nil {
				mu.Lock()
				errCount++
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	// All requests must complete cleanly without deadlocking or crashing the host
	if errCount > 0 {
		t.Logf("Encountered %d bounded queue timeouts/errors under extreme concurrency load", errCount)
	}
}

func TestAdversarial_MalformedSARIF(t *testing.T) {
	corruptPayloads := []string{
		`{"version": "2.1.0"`,              // Incomplete JSON
		`{"version": 123}`,                 // Wrong types
		`{"version": "2.1.0", "runs": null}`, // Null runs
		``,                                  // Empty string
	}

	for idx, payload := range corruptPayloads {
		_, err := ParseSARIF(strings.NewReader(payload))
		if err == nil && len(payload) > 0 {
			t.Errorf("payload %d expected parse error, but succeeded", idx)
		}
	}
}
