package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bonjoski/aegisbox/pkg/ipc"
	"github.com/bonjoski/aegisbox/pkg/version"
	"github.com/bonjoski/aegisbox/pkg/vmm"
)

func main() {
	socketPathFlag := flag.String("socket-path", "", "Path to the local Unix domain socket or Windows Named Pipe")
	quotaFlag := flag.Int("quota", 3, "Maximum concurrent microVM instances allowed per user")
	poolSizeFlag := flag.Int("pool-size", 2, "Size of the pre-warmed snapshot pool")
	versionFlag := flag.Bool("version", false, "Print daemon version and exit")
	foregroundFlag := flag.Bool("foreground", false, "Run daemon in foreground with verbose standard logging")
	flag.Parse()

	daemonVersion := version.Version
	if *versionFlag {
		fmt.Printf("aegisboxd %s (Fabrial Sovereign Security Fabric)\n", daemonVersion)
		os.Exit(0)
	}

	socketPath := *socketPathFlag
	if socketPath == "" {
		var err error
		socketPath, err = ipc.DefaultSocketPath()
		if err != nil {
			log.Fatalf("[FATAL] Failed to determine default socket path: %v", err)
		}
	}

	if *foregroundFlag {
		log.Printf("[INFO] Initializing aegisboxd %s...", daemonVersion)
	}

	// 1. Initialize hypervisor driver
	driver := vmm.NewPlatformDriver()
	if err := driver.VerifyPrerequisites(context.Background()); err != nil {
		log.Printf("[WARN] Hardware hypervisor not available: %v. Falling back to local process driver.", err)
		driver = vmm.NewLocalProcessDriver()
	} else if *foregroundFlag {
		log.Printf("[INFO] Hypervisor driver initialized: %s", driver.Name())
	}

	// 2. Initialize supervisor
	supervisor := NewSupervisor(driver, *quotaFlag, *poolSizeFlag)

	// 3. Initialize secure token store and gRPC server
	tokenStore := ipc.NewTokenStore(24 * time.Hour)
	server := ipc.NewServer(tokenStore)
	daemonService := NewDaemonServer(supervisor, tokenStore, daemonVersion)
	server.RegisterDaemonService(daemonService)

	// 4. Bind secure local IPC listener
	listener, err := ipc.ListenSecureIPC(socketPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to bind secure IPC listener: %v", err)
	}
	defer listener.Close()

	if *foregroundFlag {
		log.Printf("[INFO] aegisboxd listening on %s (mode 0600, UID validated)", socketPath)
	}

	// 5. Start serving gRPC in background
	serverErr := make(chan error, 1)
	go func() {
		if err := server.Serve(listener); err != nil {
			serverErr <- err
		}
	}()

	// 6. Signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		if *foregroundFlag {
			log.Printf("[INFO] Received signal %v, initiating graceful shutdown...", sig)
		}
	case err := <-serverErr:
		log.Fatalf("[FATAL] Server encountered runtime error: %v", err)
	}

	// Graceful teardown
	teardownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	server.GracefulStop()
	supervisor.TeardownAll(teardownCtx)

	// Unlink socket file
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Printf("[WARN] Failed to unlink socket %s: %v", socketPath, err)
	}

	if *foregroundFlag {
		log.Printf("[INFO] aegisboxd shutdown complete.")
	}
}
