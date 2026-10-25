//go:build darwin

package ipc

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// verifyPeerCredentials verifies that the connected Unix domain socket client
// has the exact same UID as the current daemon process, eliminating cross-user
// hijacking and PID-reuse races on macOS.
func verifyPeerCredentials(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("connection is not a UnixConn: %T", conn)
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get SyscallConn: %w", err)
	}

	var verifyErr error
	controlErr := rawConn.Control(func(fd uintptr) {
		xucred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			verifyErr = fmt.Errorf("failed to retrieve peer xucred: %w", err)
			return
		}

		currentUID := uint32(os.Getuid())
		if xucred.Uid != currentUID {
			verifyErr = fmt.Errorf("caller UID %d does not match daemon UID %d (EACCES)", xucred.Uid, currentUID)
			return
		}
	})

	if controlErr != nil {
		return fmt.Errorf("raw control error: %w", controlErr)
	}
	return verifyErr
}
