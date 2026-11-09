package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
)

var (
	proxyCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")
	proxyNAT64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	proxyAWSIMDSv6   = netip.MustParseAddr("fd00:ec2::254")
)

// ValidateProxyRouteURL enforces strict https:// transport and safe public target host/IP
// validation for AEGISBOX_PROXY_ROUTE / --proxy-route entries so attacker-controlled routes
// cannot exfiltrate real host credentials over plaintext HTTP or to internal/IMDS endpoints.
func ValidateProxyRouteURL(targetRaw string) error {
	trimmed := strings.TrimSpace(targetRaw)
	if trimmed == "" {
		return fmt.Errorf("empty proxy route URL")
	}
	if idx := strings.Index(trimmed, "@"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	_, err := parseAndValidateRouteTarget(trimmed, false)
	return err
}

func parseAndValidateRouteTarget(targetRaw string, allowMockLocalHTTP bool) (*url.URL, error) {
	trimmed := strings.TrimSpace(targetRaw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty proxy route target")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "https://" + trimmed
	}

	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("malformed proxy route URL %q", targetRaw)
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return nil, fmt.Errorf("missing hostname in proxy route URL %q", targetRaw)
	}

	if scheme != "https" {
		if allowMockLocalHTTP && scheme == "http" && (host == "127.0.0.1" || host == "localhost") {
			return u, nil
		}
		return nil, fmt.Errorf("security violation: proxy route %q must use https:// scheme (got %q)", targetRaw, u.Scheme)
	}

	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		if allowMockLocalHTTP {
			return u, nil
		}
		return nil, fmt.Errorf("security violation: proxy route %q targets prohibited loopback host %q", targetRaw, host)
	}

	if addr, isIP := parseRouteIP(host); isIP {
		if isRestrictedUpstreamIP(addr) && !allowMockLocalHTTP {
			return nil, fmt.Errorf("security violation: proxy route %q targets restricted internal/metadata IP %s", targetRaw, addr.String())
		}
	}

	return u, nil
}

func safeUpstreamDialControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if pct := strings.IndexByte(host, '%'); pct != -1 {
		host = host[:pct]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("proxy dialer: invalid resolved IP %q: %w", host, err)
	}
	if isRestrictedUpstreamIP(addr) {
		return fmt.Errorf("security violation: upstream credential proxy blocked connection to restricted IP %s", addr.String())
	}
	return nil
}

func isRestrictedUpstreamIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	if addr == proxyAWSIMDSv6 {
		return true
	}
	norm := addr
	if norm.Is4In6() {
		norm = norm.Unmap()
	} else if proxyNAT64Prefix.Contains(norm) {
		b16 := norm.As16()
		norm = netip.AddrFrom4([4]byte{b16[12], b16[13], b16[14], b16[15]})
	}
	return norm.IsLoopback() ||
		norm.IsPrivate() ||
		norm.IsLinkLocalUnicast() ||
		norm.IsLinkLocalMulticast() ||
		norm.IsMulticast() ||
		norm.IsUnspecified() ||
		proxyCGNATPrefix.Contains(norm)
}

func parseRouteIP(host string) (netip.Addr, bool) {
	clean := strings.Trim(host, "[]")
	if pct := strings.IndexByte(clean, '%'); pct != -1 {
		clean = clean[:pct]
	}
	if addr, err := netip.ParseAddr(clean); err == nil {
		return addr, true
	}

	parts := strings.Split(clean, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" {
			return netip.Addr{}, false
		}
		var v uint64
		var err error
		if strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X") {
			v, err = strconv.ParseUint(p[2:], 16, 32)
		} else if len(p) > 1 && p[0] == '0' {
			v, err = strconv.ParseUint(p[1:], 8, 32)
		} else {
			v, err = strconv.ParseUint(p, 10, 32)
		}
		if err != nil {
			return netip.Addr{}, false
		}
		vals[i] = v
	}

	var ip32 uint32
	switch len(vals) {
	case 1:
		if vals[0] > 0xffffffff {
			return netip.Addr{}, false
		}
		ip32 = uint32(vals[0])
	case 2:
		if vals[0] > 0xff || vals[1] > 0xffffff {
			return netip.Addr{}, false
		}
		ip32 = uint32((vals[0] << 24) | vals[1])
	case 3:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xffff {
			return netip.Addr{}, false
		}
		ip32 = uint32((vals[0] << 24) | (vals[1] << 16) | vals[2])
	case 4:
		if vals[0] > 0xff || vals[1] > 0xff || vals[2] > 0xff || vals[3] > 0xff {
			return netip.Addr{}, false
		}
		ip32 = uint32((vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3])
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ip32)
	return netip.AddrFrom4(b), true
}
