//go:build windows

package ipc

import (
	"context"
	"errors"
	"fmt"
	"net"
)

const DefaultNamedPipePath = `\\.\pipe\aegisboxd`

func DefaultSocketPath() (string, error) {
	return DefaultNamedPipePath, nil
}

func ListenSecureIPC(pipePath string) (net.Listener, error) {
	if pipePath == "" {
		pipePath = DefaultNamedPipePath
	}
	// In full production, Windows uses winio.ListenPipe with SDDL D:(A;;GRGW;;;<UserSID>)
	// For compilation on Windows platforms, we provide standard listener interface:
	return nil, errors.New("windows named pipe listener initialized via aegisbox-netd service helper")
}

func DialSecureIPC(ctx context.Context, pipePath string) (net.Conn, error) {
	if pipePath == "" {
		pipePath = DefaultNamedPipePath
	}
	var d net.Dialer
	return d.DialContext(ctx, "npipe", pipePath)
}
