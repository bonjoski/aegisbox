//go:build !windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// DefaultSocketPath returns the standard secure location of the aegisboxd IPC socket.
func DefaultSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to determine user home directory: %w", err)
	}
	return filepath.Join(home, ".aegisbox", "aegisboxd.sock"), nil
}

// secureListener wraps a net.Listener to enforce peer credential verification
// on every accepted connection before handing it off to gRPC.
type secureListener struct {
	net.Listener
}

func (l *secureListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if err := verifyPeerCredentials(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("peer credential verification failed: %w", err)
	}

	return conn, nil
}

// ListenSecureIPC initializes the local Unix domain socket listener with strict
// adversarial filesystem permissions and peer credential verification.
func ListenSecureIPC(socketPath string) (net.Listener, error) {
	if socketPath == "" {
		var err error
		socketPath, err = DefaultSocketPath()
		if err != nil {
			return nil, err
		}
	}

	if len(socketPath) >= 104 {
		return nil, fmt.Errorf("socket path length %d exceeds POSIX sockaddr_un limit of 103 characters: %s", len(socketPath), socketPath)
	}

	parentDir := filepath.Dir(socketPath)

	// Adversarial Directory Guard: Inspect parent directory
	fi, err := os.Lstat(parentDir)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(parentDir, 0700); err != nil {
				return nil, fmt.Errorf("failed to create secure parent directory %s: %w", parentDir, err)
			}
		} else {
			return nil, fmt.Errorf("failed to stat parent directory %s: %w", parentDir, err)
		}
	} else {
		// Reject symlinks targeting the parent directory
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("security violation: parent directory %s is a symbolic link", parentDir)
		}
		// Enforce strict 0700 permissions
		if fi.Mode().Perm() != 0700 {
			if err := os.Chmod(parentDir, 0700); err != nil {
				return nil, fmt.Errorf("failed to enforce 0700 permissions on %s: %w", parentDir, err)
			}
		}
	}

	// Remove stale socket if present
	if _, err := os.Lstat(socketPath); err == nil {
		// Try connecting to test if it's alive
		testConn, dialErr := net.Dial("unix", socketPath)
		if dialErr == nil {
			_ = testConn.Close()
			return nil, errors.New("another active aegisboxd daemon is already listening on this socket")
		}
		// Stale socket, safe to unlink
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("failed to unlink stale socket %s: %w", socketPath, err)
		}
	}

	rawListener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to bind unix socket on %s: %w", socketPath, err)
	}

	// Enforce 0600 on the socket file
	if err := os.Chmod(socketPath, 0600); err != nil {
		_ = rawListener.Close()
		return nil, fmt.Errorf("failed to set 0600 permissions on socket: %w", err)
	}

	return &secureListener{Listener: rawListener}, nil
}

// DialSecureIPC establishes a client connection to the local aegisboxd socket.
func DialSecureIPC(ctx context.Context, socketPath string) (net.Conn, error) {
	if socketPath == "" {
		var err error
		socketPath, err = DefaultSocketPath()
		if err != nil {
			return nil, err
		}
	}

	var d net.Dialer
	return d.DialContext(ctx, "unix", socketPath)
}
