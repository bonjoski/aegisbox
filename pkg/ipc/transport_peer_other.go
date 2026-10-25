//go:build !darwin && !linux && !windows

package ipc

import (
	"fmt"
	"net"
)

func verifyPeerCredentials(conn net.Conn) error {
	// Fallback for unsupported POSIX platforms
	return fmt.Errorf("peer credential verification not supported on this platform")
}
