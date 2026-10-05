package argus

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// SecurityLevel defines the enforcement rigor.
type SecurityLevel string

const (
	LevelStandard SecurityLevel = "standard"
	LevelStrict   SecurityLevel = "strict"
	LevelParanoid SecurityLevel = "paranoid"
)

// IssueSeverity indicates the criticality of an AST finding.
type IssueSeverity string

const (
	SeverityHigh   IssueSeverity = "HIGH"
	SeverityMedium IssueSeverity = "MEDIUM"
	SeverityLow    IssueSeverity = "LOW"
)

// SecurityFinding describes an identified violation or suspicious pattern.
type SecurityFinding struct {
	RuleID      string        `json:"rule_id"`
	Severity    IssueSeverity `json:"severity"`
	Description string        `json:"description"`
	MatchedText string        `json:"matched_text"`
}

// ASTReport contains the static AST audit results for a command string.
type ASTReport struct {
	Command      string            `json:"command"`
	Allowed      bool              `json:"allowed"`
	Findings     []SecurityFinding `json:"findings"`
	ExtractedPkgs []PackageRef     `json:"extracted_packages,omitempty"`
}

// PackageRef represents an identified package installation attempt.
type PackageRef struct {
	Ecosystem string `json:"ecosystem"` // e.g. "pypi", "npm", "cargo"
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

// PreFlightAnalyzer inspects command strings before execution.
type PreFlightAnalyzer struct {
	level SecurityLevel
}

// NewPreFlightAnalyzer creates an analyzer with the given security level.
func NewPreFlightAnalyzer(level SecurityLevel) *PreFlightAnalyzer {
	if level == "" {
		level = LevelStrict
	}
	return &PreFlightAnalyzer{level: level}
}

var (
	// Reverse shell & TTY hijack regexes
	rePTYSpawn     = regexp.MustCompile(`(?i)pty\.spawn\(|posix_openpt|grantpt|unlockpt|openpty`)
	reReverseShell = regexp.MustCompile(`(?i)(/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|bash\s+-i|sh\s+-i|mkfifo.*\/bin\/(ba)?sh)`)
	reTIOCSTI      = regexp.MustCompile(`(?i)TIOCSTI|0x5412`)
	reMetadataIP   = regexp.MustCompile(`169\.254\.169\.254`)
	reDangerousEnv = regexp.MustCompile(`(?i)(\.env|\.git\/config|\.git\/hooks|id_rsa|id_ed25519)`)

	// Package manager install command patterns
	rePipInstall   = regexp.MustCompile(`pip(?:3)?\s+install\s+(?:-[a-zA-Z]+\s+)*([a-zA-Z0-9_\-\.]+)`)
	reNpmInstall   = regexp.MustCompile(`npm\s+(?:install|i|add)\s+(?:-[a-zA-Z\-]+\s+)*([@a-zA-Z0-9_\-\.\/]+)`)
	reCargoInstall = regexp.MustCompile(`cargo\s+install\s+([a-zA-Z0-9_\-\.]+)`)
)

// Analyze parses and audits a shell command string.
func (a *PreFlightAnalyzer) Analyze(ctx context.Context, cmdStr string) (*ASTReport, error) {
	report := &ASTReport{
		Command:  cmdStr,
		Allowed:  true,
		Findings: make([]SecurityFinding, 0),
	}

	// 1. Lexical and AST Parsing using mvdan.cc/sh
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(cmdStr), "")
	if err != nil {
		// If syntax error, flag parsing failure
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-AST-PARSE-FAIL",
			Severity:    SeverityMedium,
			Description: fmt.Sprintf("Shell syntax parsing failed: %v", err),
			MatchedText: cmdStr,
		})
	}

	// 2. Walk AST if parse succeeded
	if file != nil {
		syntax.Walk(file, func(node syntax.Node) bool {
			switch n := node.(type) {
			case *syntax.CallExpr:
				if len(n.Args) > 0 {
					var cmdArgs []string
					for _, arg := range n.Args {
						var sb strings.Builder
						syntax.NewPrinter().Print(&sb, arg)
						cmdArgs = append(cmdArgs, sb.String())
					}
					a.auditCommandCall(cmdArgs, report)
				}
			}
			return true
		})
	}

	// 3. Heuristic & Regex Security Rule Scans
	if match := rePTYSpawn.FindString(cmdStr); match != "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-ESCAPE-PTY",
			Severity:    SeverityHigh,
			Description: "Prohibited pseudo-terminal (PTY) spawn detected (subshell escape vector)",
			MatchedText: match,
		})
	}

	if match := reReverseShell.FindString(cmdStr); match != "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-ESCAPE-REVERSE-SHELL",
			Severity:    SeverityHigh,
			Description: "Interactive reverse shell pattern detected",
			MatchedText: match,
		})
	}

	if match := reTIOCSTI.FindString(cmdStr); match != "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-ESCAPE-TIOCSTI",
			Severity:    SeverityHigh,
			Description: "Terminal Input Injection (TIOCSTI ioctl) detected",
			MatchedText: match,
		})
	}

	if match := reMetadataIP.FindString(cmdStr); match != "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-EXFIL-METADATA",
			Severity:    SeverityHigh,
			Description: "Access to cloud instance metadata service (169.254.169.254) blocked",
			MatchedText: match,
		})
	}

	// 4. Package Extraction for Argus Slopsquatting Defense
	a.extractPackages(cmdStr, report)

	// Determine if command should be blocked
	for _, f := range report.Findings {
		if f.Severity == SeverityHigh {
			report.Allowed = false
			break
		}
	}

	return report, nil
}

func (a *PreFlightAnalyzer) auditCommandCall(args []string, report *ASTReport) {
	if len(args) == 0 {
		return
	}
	baseCmd := args[0]

	// Block destructive disk commands or raw kernel probes
	switch baseCmd {
	case "mkfs", "fdisk", "dd", "kexec", "insmod", "rmmod", "modprobe":
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-KERNEL-PRIVILEGED-CMD",
			Severity:    SeverityHigh,
			Description: fmt.Sprintf("Direct hardware/kernel manipulation command %q prohibited", baseCmd),
			MatchedText: baseCmd,
		})
	case "curl", "wget":
		for _, arg := range args[1:] {
			if reMetadataIP.MatchString(arg) {
				report.Findings = append(report.Findings, SecurityFinding{
					RuleID:      "SEC-EXFIL-METADATA",
					Severity:    SeverityHigh,
					Description: "Egress probe targeting metadata endpoint",
					MatchedText: arg,
				})
			}
		}
	}
}

func (a *PreFlightAnalyzer) extractPackages(cmdStr string, report *ASTReport) {
	// PyPI
	if matches := rePipInstall.FindAllStringSubmatch(cmdStr, -1); matches != nil {
		for _, m := range matches {
			if len(m) > 1 && !strings.HasPrefix(m[1], "-") {
				report.ExtractedPkgs = append(report.ExtractedPkgs, PackageRef{
					Ecosystem: "pypi",
					Name:      m[1],
				})
			}
		}
	}

	// NPM
	if matches := reNpmInstall.FindAllStringSubmatch(cmdStr, -1); matches != nil {
		for _, m := range matches {
			if len(m) > 1 && !strings.HasPrefix(m[1], "-") {
				report.ExtractedPkgs = append(report.ExtractedPkgs, PackageRef{
					Ecosystem: "npm",
					Name:      m[1],
				})
			}
		}
	}

	// Cargo
	if matches := reCargoInstall.FindAllStringSubmatch(cmdStr, -1); matches != nil {
		for _, m := range matches {
			if len(m) > 1 && !strings.HasPrefix(m[1], "-") {
				report.ExtractedPkgs = append(report.ExtractedPkgs, PackageRef{
					Ecosystem: "cargo",
					Name:      m[1],
				})
			}
		}
	}
}
