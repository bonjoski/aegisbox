package argus

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	cgnatPrefix     = netip.MustParsePrefix("100.64.0.0/10")
	nat64Prefix     = netip.MustParsePrefix("64:ff9b::/96")
	awsIPv6IMDSAddr = netip.MustParseAddr("fd00:ec2::254")
	awsIPv4IMDSAddr = netip.MustParseAddr("169.254.169.254")
	awsECSIMDSAddr  = netip.MustParseAddr("169.254.170.2")

	reURLHost       = regexp.MustCompile(`(?i)\b(?:https?|ftp|wss?|gopher|dict|ldap|tftp)://([^\s/'"` + "`" + `;|&<>]+)`)
	reDevNetHost    = regexp.MustCompile(`(?i)/dev/(?:tcp|udp)/([^\s/'"` + "`" + `;|&<>]+)/\d+`)
	reBracketedIPv6 = regexp.MustCompile(`\[([0-9a-fA-F:.%]+)\]`)
	reHexDword      = regexp.MustCompile(`\b0[xX][0-9a-fA-F]{6,8}\b`)
	reDottedExotic  = regexp.MustCompile(`\b(?:0[xX][0-9a-fA-F]+|0[0-7]+|\d+)(?:\.(?:0[xX][0-9a-fA-F]+|0[0-7]+|\d+)){1,3}\b`)
	reDecimalDword  = regexp.MustCompile(`\b\d{8,10}\b`)
)

// CanonicalizeIPTarget parses standard and exotic IP encodings (hex, octal, decimal dword,
// 2/3-part inet_aton shorthand, IPv4-mapped IPv6, bracketed IPv6, NAT64) into a canonical netip.Addr.
func CanonicalizeIPTarget(raw string) (netip.Addr, bool) {
	s := strings.TrimSpace(raw)
	s = strings.Trim(s, `"'`+"`")
	if s == "" {
		return netip.Addr{}, false
	}

	// If full URL, extract host component
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			s = u.Host
		} else {
			idx := strings.Index(s, "://")
			rest := s[idx+3:]
			if slash := strings.IndexAny(rest, "/?#"); slash != -1 {
				rest = rest[:slash]
			}
			s = rest
		}
	}

	// Strip userinfo@ if present
	if at := strings.LastIndexByte(s, '@'); at != -1 {
		s = s[at+1:]
	}

	// Handle bracketed IPv6 [addr]:port or [addr]
	if strings.HasPrefix(s, "[") {
		if end := strings.IndexByte(s, ']'); end != -1 {
			s = s[1:end]
		}
	} else if strings.Count(s, ":") == 1 {
		// Strip host:port for IPv4 / hostname / single-integer targets
		hostPart, portPart, ok := strings.Cut(s, ":")
		if ok && portPart != "" && isAllDigits(portPart) {
			s = hostPart
		}
	}

	// Strip IPv6 zone identifier (%eth0)
	if pct := strings.IndexByte(s, '%'); pct != -1 {
		s = s[:pct]
	}

	if s == "" {
		return netip.Addr{}, false
	}

	// Fast path: standard canonical IPv4 or IPv6
	if addr, err := netip.ParseAddr(s); err == nil {
		return normalizeMappedAndNAT64(addr), true
	}

	// POSIX inet_aton exotic IPv4 representations:
	// - Hex dword: 0x7f000001
	// - Octal dotted: 0177.0.0.1
	// - Mixed hex/octal/dec dotted: 0x7f.0.0.1
	// - Shorthand 2-part / 3-part: 127.1, 169.254.43518
	// - Decimal 32-bit integer: 2130706433
	if addr, ok := parseInetAton(s); ok {
		return addr, true
	}

	return netip.Addr{}, false
}

func normalizeMappedAndNAT64(addr netip.Addr) netip.Addr {
	if addr == awsIPv6IMDSAddr {
		return addr
	}
	if addr.Is4In6() {
		return addr.Unmap()
	}
	if nat64Prefix.Contains(addr) {
		b16 := addr.As16()
		return netip.AddrFrom4([4]byte{b16[12], b16[13], b16[14], b16[15]})
	}
	return addr
}

func parseInetAton(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, false
	}

	vals := make([]uint64, len(parts))
	for i, p := range parts {
		v, ok := parseInetPart(p)
		if !ok {
			return netip.Addr{}, false
		}
		vals[i] = v
	}

	var ipUint32 uint32
	switch len(vals) {
	case 1:
		if vals[0] > 0xffffffff {
			return netip.Addr{}, false
		}
		ipUint32 = uint32(vals[0])
	case 2:
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return netip.Addr{}, false
		}
		ipUint32 = uint32((vals[0] << 24) | vals[1])
	case 3:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return netip.Addr{}, false
		}
		ipUint32 = uint32((vals[0] << 24) | (vals[1] << 16) | vals[2])
	case 4:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xff || vals[3] > 0xff {
			return netip.Addr{}, false
		}
		ipUint32 = uint32((vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3])
	}

	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ipUint32)
	return netip.AddrFrom4(b), true
}

func parseInetPart(part string) (uint64, bool) {
	if part == "" {
		return 0, false
	}
	if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") {
		if len(part) <= 2 {
			return 0, false
		}
		v, err := strconv.ParseUint(part[2:], 16, 32)
		return v, err == nil
	}
	if len(part) > 1 && part[0] == '0' {
		v, err := strconv.ParseUint(part[1:], 8, 32)
		return v, err == nil
	}
	v, err := strconv.ParseUint(part, 10, 32)
	return v, err == nil
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// ClassifyCanonicalIP evaluates a canonicalized IP against cloud metadata and restricted internal ranges.
func ClassifyCanonicalIP(addr netip.Addr, matchedRaw string) (SecurityFinding, bool) {
	if !addr.IsValid() {
		return SecurityFinding{}, false
	}

	norm := normalizeMappedAndNAT64(addr)
	if addr == awsIPv6IMDSAddr || norm == awsIPv4IMDSAddr || norm == awsECSIMDSAddr {
		return SecurityFinding{
			RuleID:      "SEC-EXFIL-METADATA",
			Severity:    SeverityHigh,
			Description: fmt.Sprintf("Access to cloud instance metadata endpoint (%s) blocked", norm.String()),
			MatchedText: matchedRaw,
		}, true
	}

	if norm.IsLoopback() ||
		norm.IsPrivate() ||
		norm.IsLinkLocalUnicast() ||
		norm.IsLinkLocalMulticast() ||
		norm.IsUnspecified() ||
		cgnatPrefix.Contains(norm) {
		return SecurityFinding{
			RuleID:      "SEC-PROBE-INTERNAL-NET",
			Severity:    SeverityHigh,
			Description: fmt.Sprintf("Unauthorized internal/loopback/CGNAT network target (%s) blocked", norm.String()),
			MatchedText: matchedRaw,
		}, true
	}

	return SecurityFinding{}, false
}

// scanCanonicalIPTargets extracts URL hosts, /dev/tcp targets, bracketed IPv6 literals,
// and exotic IPv4 literals from a command string and appends high-severity findings.
func scanCanonicalIPTargets(cmdStr string, report *ASTReport) {
	seen := make(map[string]bool)
	recordCandidate := func(candidate string, allowSmallShort bool) {
		if candidate == "" || seen[candidate] {
			return
		}
		addr, ok := CanonicalizeIPTarget(candidate)
		if !ok {
			return
		}
		if !allowSmallShort {
			// Avoid false positives on 2-part version numbers like "0.5" or "10.1" outside URLs/network commands
			// unless clearly loopback (127.*), link-local (169.254.*), hex (0x*), or leading-zero octal (0177.*).
			dots := strings.Count(candidate, ".")
			if dots == 1 && !strings.HasPrefix(candidate, "127.") &&
				!strings.HasPrefix(strings.ToLower(candidate), "0x") &&
				!(len(candidate) > 1 && candidate[0] == '0') {
				return
			}
		}
		if finding, flagged := ClassifyCanonicalIP(addr, candidate); flagged {
			seen[candidate] = true
			report.Findings = append(report.Findings, finding)
		}
	}

	// 1. Explicit URL hosts (http://2130706433, http://127.1, http://[::ffff:169.254.169.254], http://[fd00:ec2::254])
	for _, m := range reURLHost.FindAllStringSubmatch(cmdStr, -1) {
		if len(m) > 1 {
			recordCandidate(m[1], true)
		}
	}

	// 2. Bash /dev/tcp and /dev/udp pseudo-device hosts
	for _, m := range reDevNetHost.FindAllStringSubmatch(cmdStr, -1) {
		if len(m) > 1 {
			recordCandidate(m[1], true)
		}
	}

	// 3. Bracketed IPv6 literals anywhere in command
	for _, m := range reBracketedIPv6.FindAllStringSubmatch(cmdStr, -1) {
		if len(m) > 0 {
			recordCandidate(m[0], true)
		}
	}

	// 4. Hex 32-bit integers (e.g. 0x7f000001, 0xa9fea9fe)
	for _, m := range reHexDword.FindAllString(cmdStr, -1) {
		recordCandidate(m, true)
	}

	// 5. Dotted exotic / standard IPv4 literals (0177.0.0.1, 127.1, 100.64.0.1, 169.254.43518)
	for _, m := range reDottedExotic.FindAllString(cmdStr, -1) {
		recordCandidate(m, false)
	}

	// 6. Bare decimal 32-bit integers in private/loopback/CGNAT/IMDS ranges (e.g. 2130706433, 2852039166)
	for _, m := range reDecimalDword.FindAllString(cmdStr, -1) {
		if v, err := strconv.ParseUint(m, 10, 64); err == nil && v >= 0x0a000000 && v <= 0xffffffff {
			recordCandidate(m, true)
		}
	}

	// 7. Unbracketed IPv6 IMDS / ULA / loopback tokens
	for _, tok := range strings.FieldsFunc(cmdStr, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\'' || r == '"' || r == '`' || r == '(' || r == ')' || r == ';' || r == ','
	}) {
		if strings.Contains(tok, ":") && !strings.Contains(tok, "://") {
			recordCandidate(tok, true)
		}
	}
}
