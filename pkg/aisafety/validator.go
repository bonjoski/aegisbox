package aisafety

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/aegisbox/pkg/argus"
)

var (
	// ErrNonLoopbackTarget indicates a fail-closed rejection of a non-loopback host or IP.
	ErrNonLoopbackTarget = errors.New("security violation: aegisbox AI-safety harness only permits strictly local loopback targets")
	// ErrNonLoopbackRedirect indicates a fail-closed rejection of an HTTP redirect leaving loopback.
	ErrNonLoopbackRedirect = errors.New("security violation: HTTP redirect to non-loopback target blocked")
	// ErrInvalidTargetSpec indicates a malformed or unsupported TargetSpec.
	ErrInvalidTargetSpec = errors.New("invalid local target specification")
)

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	// Disallowed remote-pivoting commands when executing local MCP/CLI targets.
	disallowedRemoteBinaries = map[string]bool{
		"ssh":    true,
		"scp":    true,
		"sftp":   true,
		"nc":     true,
		"ncat":   true,
		"netcat": true,
		"socat":  true,
		"telnet": true,
		"curl":   true,
		"wget":   true,
	}
)

// ResolvedLocalTarget captures a validated, IP-pinned local HTTP target.
type ResolvedLocalTarget struct {
	URL      *url.URL
	PinnedIP netip.Addr
	Port     string
}

// ValidateLocalTarget strictly validates TargetSpec to ensure 100% local workstation Safe Harbor:
// - http-local: strictly loopback (127.0.0.1, ::1, localhost), pre-dial DNS verified via net.IP.IsLoopback()
// - mcp-stdio / cli-local: local command argv (or local unix:// socket) with zero remote pivot tools
func ValidateLocalTarget(spec TargetSpec) error {
	kind := inferTargetKind(spec)
	switch kind {
	case TargetKindHTTPLocal:
		_, err := ResolveAndPinLocalHTTPURL(context.Background(), spec.Endpoint)
		return err
	case TargetKindMCPStdio, TargetKindCLILocal:
		return validateLocalCommandSpec(spec)
	default:
		return fmt.Errorf("%w: unsupported target kind %q (expected http-local, mcp-stdio, or cli-local)", ErrInvalidTargetSpec, spec.Kind)
	}
}

func inferTargetKind(spec TargetSpec) string {
	if spec.Kind != "" {
		return strings.ToLower(strings.TrimSpace(spec.Kind))
	}
	if len(spec.Command) > 0 {
		return TargetKindMCPStdio
	}
	if strings.TrimSpace(spec.Endpoint) != "" {
		return TargetKindHTTPLocal
	}
	return ""
}

func validateLocalCommandSpec(spec TargetSpec) error {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(spec.Endpoint)), "unix://") {
		sockPath := strings.TrimPrefix(strings.TrimSpace(spec.Endpoint), "unix://")
		if sockPath == "" || strings.ContainsRune(sockPath, '\x00') {
			return fmt.Errorf("%w: malformed unix socket path", ErrInvalidTargetSpec)
		}
		if strings.Contains(sockPath, "..") {
			return fmt.Errorf("%w: path traversal prohibited in unix socket path %q", ErrNonLoopbackTarget, sockPath)
		}
		return nil
	}

	if len(spec.Command) == 0 {
		return fmt.Errorf("%w: local command required for %s target", ErrInvalidTargetSpec, inferTargetKind(spec))
	}
	bin := strings.TrimSpace(spec.Command[0])
	if bin == "" || strings.ContainsRune(bin, '\x00') {
		return fmt.Errorf("%w: empty or invalid command binary", ErrInvalidTargetSpec)
	}
	for _, arg := range spec.Command {
		if strings.ContainsRune(arg, '\x00') {
			return fmt.Errorf("%w: NUL byte prohibited in command arguments", ErrInvalidTargetSpec)
		}
	}
	base := strings.ToLower(filepath.Base(bin))
	if disallowedRemoteBinaries[base] {
		return fmt.Errorf("%w: remote network binary %q prohibited in local target command", ErrNonLoopbackTarget, base)
	}
	return nil
}

// ResolveAndPinLocalHTTPURL parses rawURL, enforces strict loopback host/IP constraints,
// performs pre-dial DNS resolution, verifies EVERY resolved IP is strictly loopback,
// and returns the pinned loopback IP for subsequent dial control.
func ResolveAndPinLocalHTTPURL(ctx context.Context, rawURL string) (*ResolvedLocalTarget, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: empty HTTP target endpoint", ErrInvalidTargetSpec)
	}
	if strings.ContainsAny(trimmed, "\x00\r\n") {
		return nil, fmt.Errorf("%w: control characters prohibited in URL", ErrNonLoopbackTarget)
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed URL %q: %v", ErrInvalidTargetSpec, rawURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q not allowed (must be http or https)", ErrNonLoopbackTarget, u.Scheme)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%w: userinfo credentials prohibited in target URL", ErrNonLoopbackTarget)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: missing host in URL %q", ErrInvalidTargetSpec, rawURL)
	}

	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return nil, fmt.Errorf("%w: missing hostname in URL %q", ErrInvalidTargetSpec, rawURL)
	}

	// Strip trailing DNS dot for strict literal check
	hostNoDot := strings.TrimSuffix(host, ".")

	// Strip IPv6 zone identifier if any
	cleanHost := hostNoDot
	if pct := strings.IndexByte(cleanHost, '%'); pct != -1 {
		return nil, fmt.Errorf("%w: IPv6 zone identifiers prohibited in host %q", ErrNonLoopbackTarget, host)
	}

	// Reject exotic / literal IP encodings that do not normalize to loopback (including 0.0.0.0,
	// 169.254.169.254, ::ffff:8.8.8.8, decimal/octal/hex dwords, NAT64).
	if canonicalIP, isIP := argus.CanonicalizeIPTarget(cleanHost); isIP {
		if !isStrictLoopbackAddr(canonicalIP) {
			return nil, fmt.Errorf("%w: host %q resolved to non-loopback IP %s", ErrNonLoopbackTarget, host, canonicalIP.String())
		}
		// Reject raw ::ffff:127.0.0.1 mapped ambiguity if the user passed an unmapped non-standard form,
		// OR normalize strictly to canonical IPv4 loopback. Here we also reject non-canonical forms like 0.0.0.0.
		if parsedDirect, err := netip.ParseAddr(cleanHost); err == nil {
			if parsedDirect.Is4In6() {
				unmapped := parsedDirect.Unmap()
				if !isStrictLoopbackAddr(unmapped) {
					return nil, fmt.Errorf("%w: IPv4-mapped IPv6 %q targets non-loopback %s", ErrNonLoopbackTarget, host, unmapped.String())
				}
				// Reject IPv4-mapped IPv6 outright for maximum strictness unless explicitly pure 127.0.0.1/::1
				return nil, fmt.Errorf("%w: IPv4-mapped IPv6 host %q prohibited; use 127.0.0.1 or ::1", ErrNonLoopbackTarget, host)
			}
			if !isStrictLoopbackAddr(parsedDirect) {
				return nil, fmt.Errorf("%w: IP %s is not loopback", ErrNonLoopbackTarget, parsedDirect.String())
			}
			port := u.Port()
			if port == "" {
				if scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			return &ResolvedLocalTarget{URL: u, PinnedIP: parsedDirect, Port: port}, nil
		}
		// Reject exotic inet_aton encodings (hex/octal/dword like 0x7f000001) to prevent parser confusion.
		return nil, fmt.Errorf("%w: exotic IP encoding %q prohibited; use 127.0.0.1, ::1, or localhost", ErrNonLoopbackTarget, host)
	}

	// Hostname allowlist: ONLY literal "localhost" is permitted as a hostname.
	// Arbitrary DNS names (example.com, 127.0.0.1.nip.io, rebinding.attacker.com) are rejected fail-closed!
	if hostNoDot != "localhost" {
		return nil, fmt.Errorf("%w: non-loopback hostname %q rejected (only 127.0.0.1, ::1, or localhost allowed)", ErrNonLoopbackTarget, host)
	}

	// Pre-dial DNS resolution + verify EVERY returned IP satisfies strict loopback check.
	if ctx == nil {
		ctx = context.Background()
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", hostNoDot)
	if err != nil || len(ips) == 0 {
		// Fall back safely to 127.0.0.1 only for literal "localhost" if /etc/hosts lookup is sandboxed,
		// never for any other hostname.
		pinned := netip.MustParseAddr("127.0.0.1")
		port := defaultPort(u, scheme)
		return &ResolvedLocalTarget{URL: u, PinnedIP: pinned, Port: port}, nil
	}

	var pinned netip.Addr
	for _, ip := range ips {
		if !isStrictLoopbackNetIP(ip) {
			return nil, fmt.Errorf("%w: DNS resolution of %q returned non-loopback IP %s", ErrNonLoopbackTarget, host, ip.String())
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return nil, fmt.Errorf("%w: invalid resolved IP %v", ErrNonLoopbackTarget, ip)
		}
		addr = addr.Unmap()
		if !isStrictLoopbackAddr(addr) {
			return nil, fmt.Errorf("%w: resolved IP %s failed strict loopback verification", ErrNonLoopbackTarget, addr.String())
		}
		// Prefer IPv4 127.0.0.1 first when both 127.0.0.1 and ::1 are returned.
		if !pinned.IsValid() || (pinned.Is6() && addr.Is4()) {
			pinned = addr
		}
	}

	if !pinned.IsValid() {
		return nil, fmt.Errorf("%w: failed to pin loopback IP for %q", ErrNonLoopbackTarget, host)
	}

	return &ResolvedLocalTarget{
		URL:      u,
		PinnedIP: pinned,
		Port:     defaultPort(u, scheme),
	}, nil
}

func defaultPort(u *url.URL, scheme string) string {
	if p := u.Port(); p != "" {
		return p
	}
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func isStrictLoopbackNetIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if !ip.IsLoopback() {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return isStrictLoopbackAddr(addr)
}

func isStrictLoopbackAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if nat64Prefix.Contains(addr) {
		return false
	}
	if addr.IsUnspecified() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return false
	}
	return addr.IsLoopback()
}

// NewLoopbackPinnedHTTPClient constructs an *http.Client that:
// 1. Pins all socket dials via net.Dialer.Control to strictly verified loopback IPs (and pinnedIP if valid).
// 2. Resolves & dials the pinned IP directly to prevent DNS rebinding TOCTOU races.
// 3. Enforces CheckRedirect to block ANY redirect to a non-loopback host/IP.
func NewLoopbackPinnedHTTPClient(timeout time.Duration, pinnedIP netip.Addr) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 15 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			if pct := strings.IndexByte(host, '%'); pct != -1 {
				host = host[:pct]
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("%w: dialer control invalid IP %q", ErrNonLoopbackTarget, host)
			}
			if addr.Is4In6() {
				addr = addr.Unmap()
			}
			if !isStrictLoopbackAddr(addr) {
				return fmt.Errorf("%w: dialer control blocked non-loopback IP %s", ErrNonLoopbackTarget, addr.String())
			}
			if pinnedIP.IsValid() {
				normPinned := pinnedIP.Unmap()
				if addr != normPinned {
					return fmt.Errorf("%w: dialer control detected IP drift (got %s, pinned %s)", ErrNonLoopbackTarget, addr.String(), normPinned.String())
				}
			}
			return nil
		},
	}

	transport := &http.Transport{
		Proxy: nil, // Never route loopback safety probes through ambient HTTP_PROXY/HTTPS_PROXY!
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: malformed dial address %q", ErrNonLoopbackTarget, addr)
			}
			// Re-verify target before dialing and dial pinned IP directly.
			targetURL := fmt.Sprintf("http://%s", net.JoinHostPort(host, port))
			resolved, err := ResolveAndPinLocalHTTPURL(ctx, targetURL)
			if err != nil {
				return nil, err
			}
			dialIP := resolved.PinnedIP
			if pinnedIP.IsValid() {
				dialIP = pinnedIP.Unmap()
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(dialIP.String(), port))
		},
		MaxIdleConns:          8,
		IdleConnTimeout:       15 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("%w: too many redirects", ErrNonLoopbackRedirect)
			}
			resolved, err := ResolveAndPinLocalHTTPURL(req.Context(), req.URL.String())
			if err != nil {
				return fmt.Errorf("%w: %v", ErrNonLoopbackRedirect, err)
			}
			if pinnedIP.IsValid() && resolved.PinnedIP.Unmap() != pinnedIP.Unmap() {
				return fmt.Errorf("%w: redirect switched IP from %s to %s", ErrNonLoopbackRedirect, pinnedIP.String(), resolved.PinnedIP.String())
			}
			return nil
		},
	}
}
