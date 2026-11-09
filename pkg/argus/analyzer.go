package argus

import (
	"context"
	"fmt"
	"path/filepath"
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
	Command       string            `json:"command"`
	Allowed       bool              `json:"allowed"`
	Findings      []SecurityFinding `json:"findings"`
	ExtractedPkgs []PackageRef      `json:"extracted_packages,omitempty"`
}

// PackageRef represents an identified package installation attempt.
type PackageRef struct {
	Ecosystem string `json:"ecosystem"` // e.g. "pypi", "npm", "cargo", "golang"
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
}

// PreFlightAnalyzer inspects command strings before execution.
type PreFlightAnalyzer struct {
	level    SecurityLevel
	verifier PackageVerifier
}

// NewPreFlightAnalyzer creates an analyzer with the given security level.
func NewPreFlightAnalyzer(level SecurityLevel) *PreFlightAnalyzer {
	if level == "" {
		level = LevelStrict
	}
	return &PreFlightAnalyzer{level: level}
}

// WithPackageVerifier attaches a package verifier to the analyzer for slopsquatting checks.
func (a *PreFlightAnalyzer) WithPackageVerifier(v PackageVerifier) *PreFlightAnalyzer {
	a.verifier = v
	return a
}

var (
	// Reverse shell & TTY hijack regexes
	rePTYSpawn         = regexp.MustCompile(`(?i)pty\.spawn\(|posix_openpt|grantpt|unlockpt|openpty`)
	reReverseShell     = regexp.MustCompile(`(?i)(/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|bash\s+-i|sh\s+-i|mkfifo.*\/bin\/(ba)?sh)`)
	reTIOCSTI          = regexp.MustCompile(`(?i)TIOCSTI|0x5412|0x80017472`)
	reMetadataIP       = regexp.MustCompile(`(?i)(169\.254\.169\.254|fd00:ec2::254)`)
	reDangerousEnv     = regexp.MustCompile(`(?i)(\.env|\.git\/config|\.git\/hooks|id_rsa|id_ed25519)`)
	reInternalSubnet   = regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?|192\.168\.\d{1,3}\.\d{1,3}(/\d{1,2})?|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}(/\d{1,2})?|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(/\d{1,2})?)\b`)
	reForkBomb         = regexp.MustCompile(`(?i)(:\{\s*:\|:&\s*\};:|:\(\)\s*\{\s*:\|:&\s*\};:|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\(\)\s*\{\s*.*\|.*&\s*\};|while\s+true\s*;?\s*do\s+.*&\s*done)`)
	reMemoryExhaustion = regexp.MustCompile(`(?i)(10\*\*10|10\^10|10000000000|/dev/zero\b|stress\s+--vm|--vm-bytes)`)
	rePathTraversal    = regexp.MustCompile(`(?i)(\.\./\.\.|\.\./etc/|/etc/(passwd|shadow|sudoers|hosts|crontab|cron\.d)|\b/root/\b|\b/boot/\b)`)
	reOSCInjection     = regexp.MustCompile(`(?i)(\\033\]52|\\x1b\]52|\]52;c;)`)
	reDNSTunneling     = regexp.MustCompile(`(?i)\b(dig|nslookup|host)\b.*(@|\bexfil|attacker\.com|\.burpcollaborator\.net|\.oast\b)`)
)

// Analyze parses and audits a shell command string.
func (a *PreFlightAnalyzer) Analyze(ctx context.Context, cmdStr string) (*ASTReport, error) {
	report := &ASTReport{
		Command:  cmdStr,
		Allowed:  true,
		Findings: make([]SecurityFinding, 0),
	}

	if strings.TrimSpace(cmdStr) == "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-AST-PARSE-FAIL",
			Severity:    SeverityHigh,
			Description: "Empty command string rejected",
			MatchedText: cmdStr,
		})
		report.Allowed = false
		return report, nil
	}

	// 1. Lexical and AST Parsing using mvdan.cc/sh (fail-closed on unparseable syntax)
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(cmdStr), "")
	if err != nil {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-AST-PARSE-FAIL",
			Severity:    SeverityHigh,
			Description: fmt.Sprintf("Shell syntax parsing failed (fail-closed): %v", err),
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
						cmdArgs = append(cmdArgs, unquoteShellWord(sb.String()))
					}
					a.auditCommandCall(cmdArgs, report)
				}
			}
			return true
		})
	}

	// 3. Canonical IP scan across exotic encodings (hex, octal, dword, shorthand, IPv4-mapped IPv6, IPv6 IMDS, CGNAT)
	scanCanonicalIPTargets(cmdStr, report)

	// 4. Heuristic & Regex Security Rule Scans
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
		appendUniqueFinding(report, SecurityFinding{
			RuleID:      "SEC-EXFIL-METADATA",
			Severity:    SeverityHigh,
			Description: "Access to cloud instance metadata service blocked",
			MatchedText: match,
		})
	}

	if match := reInternalSubnet.FindString(cmdStr); match != "" {
		appendUniqueFinding(report, SecurityFinding{
			RuleID:      "SEC-PROBE-INTERNAL-NET",
			Severity:    SeverityHigh,
			Description: "Unauthorized internal private subnet probing or lateral scan detected",
			MatchedText: match,
		})
	}

	if match := reDangerousEnv.FindString(cmdStr); match != "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-EXFIL-SECRET-FILE",
			Severity:    SeverityHigh,
			Description: "Attempted access or exfiltration of sensitive credential or repository file detected",
			MatchedText: match,
		})
	}

	if match := reForkBomb.FindString(cmdStr); match != "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-DOS-FORKBOMB",
			Severity:    SeverityHigh,
			Description: "Fork bomb / PID exhaustion pattern detected",
			MatchedText: match,
		})
	}

	if match := reMemoryExhaustion.FindString(cmdStr); match != "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-DOS-OOM",
			Severity:    SeverityHigh,
			Description: "Unbounded memory allocation / OOM exhaustion vector detected",
			MatchedText: match,
		})
	}

	if match := rePathTraversal.FindString(cmdStr); match != "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-PATH-TRAVERSAL",
			Severity:    SeverityHigh,
			Description: "Path traversal or unauthorized host system file access detected",
			MatchedText: match,
		})
	}

	if match := reOSCInjection.FindString(cmdStr); match != "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-ESCAPE-OSC52",
			Severity:    SeverityHigh,
			Description: "Terminal OSC 52 clipboard injection escape sequence detected",
			MatchedText: match,
		})
	}

	if match := reDNSTunneling.FindString(cmdStr); match != "" {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-EXFIL-DNS-TUNNEL",
			Severity:    SeverityHigh,
			Description: "Covert DNS tunneling / external resolver probing detected",
			MatchedText: match,
		})
	}

	// 5. Package Verification for Argus Slopsquatting Defense across ALL extracted packages
	if a.verifier != nil && len(report.ExtractedPkgs) > 0 {
		for _, pkg := range report.ExtractedPkgs {
			res, err := a.verifier.VerifyPackage(ctx, pkg)
			if err == nil && (!res.ExistsInIndex || res.IsSlopsquat) {
				report.Findings = append(report.Findings, SecurityFinding{
					RuleID:      "SEC-PKG-SLOPSQUAT",
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("Hallucinated/non-existent package %s:%s flagged as slopsquat", pkg.Ecosystem, pkg.Name),
					MatchedText: pkg.Name,
				})
			}
		}
	}

	// Determine if command should be blocked
	for _, f := range report.Findings {
		if f.Severity == SeverityHigh {
			report.Allowed = false
			break
		}
	}

	return report, nil
}

func appendUniqueFinding(report *ASTReport, f SecurityFinding) {
	for _, existing := range report.Findings {
		if existing.RuleID == f.RuleID && existing.MatchedText == f.MatchedText {
			return
		}
	}
	report.Findings = append(report.Findings, f)
}

func unquoteShellWord(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func isEnvAssignmentWord(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9' && i > 0) || c == '_') {
			return false
		}
	}
	return true
}

// unwrapCommandPrefixes peels off leading environment assignments and wrapper binaries
// (env, command, builtin, nohup, sudo, doas, nice, time, stdbuf, timeout) to expose the real executable.
func unwrapCommandPrefixes(args []string) []string {
	cur := args
	for len(cur) > 0 {
		if isEnvAssignmentWord(cur[0]) {
			cur = cur[1:]
			continue
		}

		base := filepath.Base(cur[0])
		switch base {
		case "env":
			cur = cur[1:]
			for len(cur) > 0 {
				tok := cur[0]
				if tok == "--" {
					cur = cur[1:]
					break
				}
				if tok == "-u" || tok == "--unset" || tok == "-C" || tok == "--chdir" || tok == "-S" {
					if len(cur) >= 2 {
						cur = cur[2:]
					} else {
						cur = nil
					}
					continue
				}
				if strings.HasPrefix(tok, "-") || isEnvAssignmentWord(tok) {
					cur = cur[1:]
					continue
				}
				break
			}
			continue

		case "command", "builtin":
			cur = cur[1:]
			hasQueryFlag := false
			for len(cur) > 0 && strings.HasPrefix(cur[0], "-") {
				if cur[0] == "-v" || cur[0] == "-V" {
					hasQueryFlag = true
				}
				if cur[0] == "--" {
					cur = cur[1:]
					break
				}
				cur = cur[1:]
			}
			if hasQueryFlag {
				return nil
			}
			continue

		case "nohup", "time":
			cur = cur[1:]
			for len(cur) > 0 && strings.HasPrefix(cur[0], "-") {
				if cur[0] == "--" {
					cur = cur[1:]
					break
				}
				cur = cur[1:]
			}
			continue

		case "sudo", "doas":
			cur = cur[1:]
			for len(cur) > 0 {
				tok := cur[0]
				if tok == "--" {
					cur = cur[1:]
					break
				}
				if tok == "-u" || tok == "-g" || tok == "-C" || tok == "-h" || tok == "-p" || tok == "-r" || tok == "-t" {
					if len(cur) >= 2 {
						cur = cur[2:]
					} else {
						cur = nil
					}
					continue
				}
				if strings.HasPrefix(tok, "-") || isEnvAssignmentWord(tok) {
					cur = cur[1:]
					continue
				}
				break
			}
			continue

		case "nice":
			cur = cur[1:]
			for len(cur) > 0 && strings.HasPrefix(cur[0], "-") {
				if cur[0] == "-n" && len(cur) >= 2 {
					cur = cur[2:]
					continue
				}
				if cur[0] == "--" {
					cur = cur[1:]
					break
				}
				cur = cur[1:]
			}
			continue

		case "timeout":
			cur = cur[1:]
			for len(cur) > 0 && strings.HasPrefix(cur[0], "-") {
				if (cur[0] == "-k" || cur[0] == "-s") && len(cur) >= 2 {
					cur = cur[2:]
					continue
				}
				if cur[0] == "--" {
					cur = cur[1:]
					break
				}
				cur = cur[1:]
			}
			// Skip timeout duration positional argument
			if len(cur) > 0 {
				cur = cur[1:]
			}
			continue
		}

		break
	}
	return cur
}

func (a *PreFlightAnalyzer) auditCommandCall(args []string, report *ASTReport) {
	effective := unwrapCommandPrefixes(args)
	if len(effective) == 0 {
		return
	}

	rawCmd := effective[0]
	baseCmd := filepath.Base(rawCmd)

	// If subshell wrapper like `sh -c "..."` or `bash -c "..."`, recursively audit inner script
	if (baseCmd == "sh" || baseCmd == "bash" || baseCmd == "zsh" || baseCmd == "dash") && len(effective) >= 3 {
		for i := 1; i < len(effective)-1; i++ {
			if effective[i] == "-c" || effective[i] == "-lc" {
				innerReport, err := a.Analyze(context.Background(), effective[i+1])
				if err == nil && innerReport != nil {
					for _, f := range innerReport.Findings {
						appendUniqueFinding(report, f)
					}
					for _, p := range innerReport.ExtractedPkgs {
						appendUniquePackage(report, p)
					}
				}
				break
			}
		}
	}

	// Block destructive disk commands or raw kernel probes (normalized across /bin/dd, /sbin/mkfs.ext4, etc.)
	if isPrivilegedKernelCommand(baseCmd) {
		report.Findings = append(report.Findings, SecurityFinding{
			RuleID:      "SEC-KERNEL-PRIVILEGED-CMD",
			Severity:    SeverityHigh,
			Description: fmt.Sprintf("Direct hardware/kernel manipulation command %q prohibited", baseCmd),
			MatchedText: rawCmd,
		})
	}

	// Inspect arguments of network utilities for canonicalized IP targets (including 127.1, 2130706433, 0x7f000001, etc.)
	switch baseCmd {
	case "curl", "wget", "nc", "ncat", "netcat", "socat", "ping", "ping6", "ssh", "scp", "sftp", "telnet", "nmap":
		skipNext := false
		for _, arg := range effective[1:] {
			if skipNext {
				skipNext = false
				continue
			}
			switch arg {
			case "-p", "--port", "-c", "-w", "-W", "-m", "--max-time", "--connect-timeout", "-t", "--retry", "-H", "--header", "-o", "-O", "-d", "--data", "-X", "--request", "-u", "--user":
				skipNext = true
				continue
			}
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if addr, ok := CanonicalizeIPTarget(arg); ok {
				if finding, flagged := ClassifyCanonicalIP(addr, arg); flagged {
					appendUniqueFinding(report, finding)
				}
			}
		}
	}

	// Extract ALL packages installed by package managers in this AST CallExpr
	extractPackagesFromCall(baseCmd, effective[1:], report)
}

func isPrivilegedKernelCommand(baseCmd string) bool {
	if strings.HasPrefix(baseCmd, "mkfs.") || strings.HasPrefix(baseCmd, "fsck.") {
		return true
	}
	switch baseCmd {
	case "mkfs", "fdisk", "sfdisk", "parted", "dd", "kexec", "insmod", "rmmod", "modprobe", "losetup", "pivot_root":
		return true
	}
	return false
}

func appendUniquePackage(report *ASTReport, pkg PackageRef) {
	if pkg.Name == "" {
		return
	}
	for _, existing := range report.ExtractedPkgs {
		if existing.Ecosystem == pkg.Ecosystem && existing.Name == pkg.Name {
			return
		}
	}
	report.ExtractedPkgs = append(report.ExtractedPkgs, pkg)
}

func extractPackagesFromCall(baseCmd string, args []string, report *ASTReport) {
	// Unwrap `python -m pip ...` or `uv pip ...`
	if (baseCmd == "python" || baseCmd == "python3") && len(args) >= 2 && args[0] == "-m" && (args[1] == "pip" || args[1] == "pip3") {
		baseCmd = "pip"
		args = args[2:]
	} else if baseCmd == "uv" && len(args) >= 1 && args[0] == "pip" {
		baseCmd = "pip"
		args = args[1:]
	}

	switch baseCmd {
	case "pip", "pip3":
		subIdx := findSubcommand(args, map[string]bool{"install": true})
		if subIdx == -1 {
			return
		}
		skipValFlags := map[string]bool{
			"-r": true, "--requirement": true,
			"-c": true, "--constraint": true,
			"-i": true, "--index-url": true, "--extra-index-url": true,
			"-f": true, "--find-links": true,
			"-t": true, "--target": true, "--prefix": true, "--root": true,
			"-e": true, "--editable": true,
		}
		skipNext := false
		for _, raw := range args[subIdx+1:] {
			if skipNext {
				skipNext = false
				continue
			}
			if skipValFlags[raw] {
				skipNext = true
				continue
			}
			if strings.HasPrefix(raw, "-") {
				continue
			}
			if name, ver, ok := cleanPyPIPackage(raw); ok {
				appendUniquePackage(report, PackageRef{Ecosystem: "pypi", Name: name, Version: ver})
			}
		}

	case "npm", "pnpm", "yarn", "bun":
		validSubs := map[string]bool{"install": true, "i": true, "add": true}
		subIdx := findSubcommand(args, validSubs)
		if subIdx == -1 {
			return
		}
		skipValFlags := map[string]bool{
			"--registry": true, "--prefix": true, "--cache": true, "-C": true, "--dir": true,
		}
		skipNext := false
		for _, raw := range args[subIdx+1:] {
			if skipNext {
				skipNext = false
				continue
			}
			if skipValFlags[raw] {
				skipNext = true
				continue
			}
			if strings.HasPrefix(raw, "-") {
				continue
			}
			if name, ver, ok := cleanNPMPackage(raw); ok {
				appendUniquePackage(report, PackageRef{Ecosystem: "npm", Name: name, Version: ver})
			}
		}

	case "cargo":
		subIdx := findSubcommand(args, map[string]bool{"add": true, "install": true})
		if subIdx == -1 {
			return
		}
		skipValFlags := map[string]bool{
			"--path": true, "--git": true, "--branch": true, "--tag": true, "--rev": true,
			"--features": true, "-F": true, "--bin": true, "--example": true, "--root": true, "--index": true, "--registry": true,
		}
		skipNext := false
		for _, raw := range args[subIdx+1:] {
			if skipNext {
				skipNext = false
				continue
			}
			if skipValFlags[raw] {
				skipNext = true
				continue
			}
			if strings.HasPrefix(raw, "-") {
				continue
			}
			if name, ver, ok := cleanCargoPackage(raw); ok {
				appendUniquePackage(report, PackageRef{Ecosystem: "cargo", Name: name, Version: ver})
			}
		}

	case "go":
		subIdx := findSubcommand(args, map[string]bool{"get": true, "install": true})
		if subIdx == -1 {
			return
		}
		skipValFlags := map[string]bool{
			"-modfile": true, "-ldflags": true, "-gcflags": true, "-asmflags": true, "-tags": true, "-pkgdir": true,
		}
		skipNext := false
		for _, raw := range args[subIdx+1:] {
			if skipNext {
				skipNext = false
				continue
			}
			if skipValFlags[raw] {
				skipNext = true
				continue
			}
			if strings.HasPrefix(raw, "-") {
				continue
			}
			if name, ver, ok := cleanGoPackage(raw); ok {
				appendUniquePackage(report, PackageRef{Ecosystem: "golang", Name: name, Version: ver})
			}
		}
	}
}

func findSubcommand(args []string, targets map[string]bool) int {
	for i, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		if targets[a] {
			return i
		}
		return -1
	}
	return -1
}

func cleanPyPIPackage(raw string) (string, string, bool) {
	if isLocalOrURLSpec(raw) {
		return "", "", false
	}
	spec := raw
	var ver string
	for _, sep := range []string{"===", "~=", "==", "!=", ">=", "<=", ">", "<", "@"} {
		if idx := strings.Index(spec, sep); idx > 0 {
			ver = strings.TrimSpace(spec[idx+len(sep):])
			spec = spec[:idx]
			break
		}
	}
	if br := strings.IndexByte(spec, '['); br > 0 {
		spec = spec[:br]
	}
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "." {
		return "", "", false
	}
	return spec, ver, true
}

func cleanNPMPackage(raw string) (string, string, bool) {
	if isLocalOrURLSpec(raw) || strings.HasPrefix(raw, "file:") || strings.HasPrefix(raw, "link:") || strings.HasPrefix(raw, "workspace:") {
		return "", "", false
	}
	spec := raw
	var ver string
	if strings.HasPrefix(spec, "@") {
		if at := strings.IndexByte(spec[1:], '@'); at != -1 {
			ver = spec[1+at+1:]
			spec = spec[:1+at]
		}
	} else if at := strings.IndexByte(spec, '@'); at > 0 {
		ver = spec[at+1:]
		spec = spec[:at]
	}
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "." {
		return "", "", false
	}
	return spec, ver, true
}

func cleanCargoPackage(raw string) (string, string, bool) {
	if isLocalOrURLSpec(raw) {
		return "", "", false
	}
	spec, ver, _ := strings.Cut(raw, "@")
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "." {
		return "", "", false
	}
	return spec, ver, true
}

func cleanGoPackage(raw string) (string, string, bool) {
	if raw == "." || strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../") || strings.HasPrefix(raw, "/") {
		return "", "", false
	}
	if raw == "all" || raw == "std" || raw == "cmd" || raw == "tool" || raw == "toolchain" || raw == "go" {
		return "", "", false
	}
	spec, ver, _ := strings.Cut(raw, "@")
	spec = strings.TrimSuffix(spec, "/...")
	// Require a domain dot in the first path element for external modules
	first, _, _ := strings.Cut(spec, "/")
	if !strings.Contains(first, ".") {
		return "", "", false
	}
	return spec, ver, true
}

func isLocalOrURLSpec(raw string) bool {
	return raw == "." ||
		strings.HasPrefix(raw, "./") ||
		strings.HasPrefix(raw, "../") ||
		strings.HasPrefix(raw, "/") ||
		strings.HasPrefix(raw, "http://") ||
		strings.HasPrefix(raw, "https://") ||
		strings.HasPrefix(raw, "git+")
}
