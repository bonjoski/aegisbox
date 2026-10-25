package main

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

var (
	// tapRegex enforces strict alphanumeric interface names to prevent command injection and host interface tampering.
	tapRegex = regexp.MustCompile(`^(aegis-tap[0-9]{1,4}|lo0|dummy0)$`)
	// anchorRegex enforces safe anchor identifier strings.
	anchorRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)

	ErrInvalidInterfaceName = errors.New("interface name must match ^(aegis-tap[0-9]{1,4}|lo0|dummy0)$")
	ErrInvalidAnchorID      = errors.New("anchor ID must match ^[a-zA-Z0-9_-]{1,32}$")
	ErrInvalidIPAddress     = errors.New("invalid IP address or CIDR format")
)

// ValidateInterfaceName ensures the target network interface matches safe, expected patterns.
func ValidateInterfaceName(name string) error {
	if !tapRegex.MatchString(name) {
		return fmt.Errorf("%w: got %q", ErrInvalidInterfaceName, name)
	}
	return nil
}

// ValidateAnchorID ensures the firewall anchor ID is safe and strictly alphanumeric.
func ValidateAnchorID(id string) error {
	if !anchorRegex.MatchString(id) {
		return fmt.Errorf("%w: got %q", ErrInvalidAnchorID, id)
	}
	return nil
}

// ValidateIPOrCIDR verifies that an IP address or subnet parses strictly via net/netip.
func ValidateIPOrCIDR(s string) error {
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return nil
	}
	return fmt.Errorf("%w: %q", ErrInvalidIPAddress, s)
}
