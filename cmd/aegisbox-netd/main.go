package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/bonjoski/aegisbox/pkg/ipc"
	ipcv1 "github.com/bonjoski/aegisbox/pkg/ipc/v1"
	"github.com/bonjoski/aegisbox/pkg/version"
	"google.golang.org/grpc"
)

const defaultNetdSocket = "/var/run/aegisbox-netd.sock"

func main() {
	socketPathFlag := flag.String("socket-path", defaultNetdSocket, "Path to the root-owned privileged netd Unix socket or Windows pipe")
	foregroundFlag := flag.Bool("foreground", false, "Run in foreground with verbose standard logging")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Printf("aegisbox-netd %s (Privileged Network Helper)\n", version.Version)
		os.Exit(0)
	}

	socketPath := *socketPathFlag
	if *foregroundFlag {
		log.Printf("[INFO] Initializing aegisbox-netd %s...", version.Version)
	}

	// 1. Initialize gRPC server
	grpcServer := grpc.NewServer()
	netdServer := NewNetdServer()
	ipcv1.RegisterAegisboxNetdServiceServer(grpcServer, netdServer)

	// 2. Bind secure listener
	listener, err := ipc.ListenSecureIPC(socketPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to bind privileged listener on %s: %v", socketPath, err)
	}
	defer listener.Close()

	if *foregroundFlag {
		log.Printf("[INFO] aegisbox-netd listening on %s", socketPath)
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			serverErr <- err
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		if *foregroundFlag {
			log.Printf("[INFO] Received signal %v, shutting down...", sig)
		}
	case err := <-serverErr:
		log.Fatalf("[FATAL] Server runtime error: %v", err)
	}

	grpcServer.GracefulStop()
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Printf("[WARN] Failed to unlink socket %s: %v", socketPath, err)
	}

	if *foregroundFlag {
		log.Printf("[INFO] aegisbox-netd shutdown complete.")
	}
}
