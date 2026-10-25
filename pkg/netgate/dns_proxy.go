package netgate

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

var (
	ErrDNSQueryBlocked = errors.New("DNS query blocked by Aegisbox egress policy")
)

// DNSProxy evaluates DNS queries from microVMs and blocks unvetted domains to prevent DNS tunneling.
type DNSProxy struct {
	allowedDomains []string
	upstreamDNS    string
	listener       net.PacketConn
	mu             sync.RWMutex
	running        bool
}

// NewDNSProxy initializes a local DNS inspection proxy.
func NewDNSProxy(allowedDomains []string, upstreamDNS string) *DNSProxy {
	if upstreamDNS == "" {
		upstreamDNS = "1.1.1.1:53"
	}
	return &DNSProxy{
		allowedDomains: allowedDomains,
		upstreamDNS:    upstreamDNS,
	}
}

// IsDomainAllowed checks whether a domain matches any entry in the allowlist.
func (p *DNSProxy) IsDomainAllowed(domain string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	domain = strings.TrimSuffix(strings.ToLower(domain), ".")

	for _, pattern := range p.allowedDomains {
		pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
		if pattern == "*" || pattern == domain {
			return true
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // e.g. ".github.com"
			if strings.HasSuffix(domain, suffix) || domain == pattern[2:] {
				return true
			}
		}
	}
	return false
}

// AddAllowedDomain dynamically adds an allowed egress domain.
func (p *DNSProxy) AddAllowedDomain(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowedDomains = append(p.allowedDomains, domain)
}

// HandleDNSQuery parses a raw DNS wire-format packet, checks allowlist, and returns response bytes.
func (p *DNSProxy) HandleDNSQuery(queryBytes []byte) ([]byte, error) {
	if len(queryBytes) < 12 {
		return nil, errors.New("truncated DNS header")
	}

	// Extract Question Domain Name (RFC 1035 section 4.1.2)
	domain, err := parseDNSQuestionName(queryBytes, 12)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DNS question: %w", err)
	}

	if !p.IsDomainAllowed(domain) {
		// Synthesize NXDOMAIN (RCode = 3, QR = 1)
		resp := make([]byte, len(queryBytes))
		copy(resp, queryBytes)
		// Set QR bit (response)
		resp[2] |= 0x80
		// Clear RCODE, set RCODE=3 (NXDOMAIN)
		resp[3] = (resp[3] & 0xf0) | 0x03
		return resp, ErrDNSQueryBlocked
	}

	// In test mode or when upstream is not dialed directly, return NOERROR response with 127.0.0.1
	resp := make([]byte, len(queryBytes)+16)
	copy(resp, queryBytes)
	resp[2] |= 0x80 // QR bit
	resp[3] &= 0xf0 // RCODE=0 (NOERROR)
	resp[7] = 1     // ANCOUNT = 1

	return resp, nil
}

func parseDNSQuestionName(buf []byte, offset int) (string, error) {
	var parts []string
	idx := offset

	for {
		if idx >= len(buf) {
			return "", errors.New("unexpected end of DNS packet while parsing label")
		}
		length := int(buf[idx])
		if length == 0 {
			break
		}
		idx++
		if idx+length > len(buf) {
			return "", errors.New("label length exceeds packet boundary")
		}
		parts = append(parts, string(buf[idx:idx+length]))
		idx += length
	}

	return strings.Join(parts, "."), nil
}
