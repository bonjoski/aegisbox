package fuzz

import (
	"testing"

	"github.com/bonjoski/aegisbox/pkg/netgate"
)

// FuzzDNSProxyDomainEvaluation fuzzes domain evaluation against tunneling payloads and malicious strings.
func FuzzDNSProxyDomainEvaluation(f *testing.F) {
	f.Add("github.com")
	f.Add("api.github.com")
	f.Add("aW1wb3J0YW50X3NlY3JldA==.attacker.com")
	f.Add("very.long.subdomain.label.with.many.dots.and.special-characters.com")
	f.Add("")
	f.Add("\x00\x01\x02")

	proxy := netgate.NewDNSProxy([]string{"*.github.com", "registry.npmjs.org"}, "1.1.1.1:53")

	f.Fuzz(func(t *testing.T, domain string) {
		// Ensure IsDomainAllowed never panics on arbitrary string input
		_ = proxy.IsDomainAllowed(domain)
	})
}
