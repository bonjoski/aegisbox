package bridge

import (
	"context"
	"net"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestFrameEncoding(t *testing.T) {
	testCases := []struct {
		name    string
		frame   Frame
		exitVal int
	}{
		{
			name:    "Signal INT",
			frame:   Frame{Type: MsgSignal, Payload: uint32(syscall.SIGINT)},
			exitVal: 0,
		},
		{
			name:    "Exit Zero",
			frame:   Frame{Type: MsgExit, Payload: ExitCodeToPayload(0)},
			exitVal: 0,
		},
		{
			name:    "Exit Negative Code",
			frame:   Frame{Type: MsgExit, Payload: ExitCodeToPayload(-1)},
			exitVal: -1,
		},
		{
			name:    "Exit 137 (SIGKILL / OOM)",
			frame:   Frame{Type: MsgExit, Payload: ExitCodeToPayload(137)},
			exitVal: 137,
		},
		{
			name:    "OOM Event",
			frame:   Frame{Type: MsgOOM, Payload: 1000},
			exitVal: 0,
		},
		{
			name:    "Heartbeat Sequence",
			frame:   Frame{Type: MsgHeartbeat, Payload: 42},
			exitVal: 0,
		},
		{
			name:    "Heartbeat ACK",
			frame:   Frame{Type: MsgHeartbeatAck, Payload: 42},
			exitVal: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, w := net.Pipe()
			defer r.Close()
			defer w.Close()

			errChan := make(chan error, 1)
			go func() {
				errChan <- WriteFrame(w, tc.frame)
			}()

			got, err := ReadFrame(r)
			if err != nil {
				t.Fatalf("ReadFrame failed: %v", err)
			}
			if writeErr := <-errChan; writeErr != nil {
				t.Fatalf("WriteFrame failed: %v", writeErr)
			}

			if got.Type != tc.frame.Type {
				t.Errorf("Expected Type 0x%02x, got 0x%02x", tc.frame.Type, got.Type)
			}
			if got.Payload != tc.frame.Payload {
				t.Errorf("Expected Payload %d, got %d", tc.frame.Payload, got.Payload)
			}

			if tc.frame.Type == MsgExit {
				decCode := PayloadToExitCode(got.Payload)
				if decCode != tc.exitVal {
					t.Errorf("Expected exit code %d, got %d", tc.exitVal, decCode)
				}
			}
		})
	}
}

func TestHostToGuestSignalForwarding(t *testing.T) {
	hostConn, guestConn := net.Pipe()
	defer hostConn.Close()
	defer guestConn.Close()

	// Spawn a real child process to receive signals
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start child process: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	signalReceived := make(chan syscall.Signal, 1)
	guest := NewGuestInit(guestConn, GuestInitOpts{
		InitialPID: cmd.Process.Pid,
		OnSignalReceived: func(sig syscall.Signal) {
			signalReceived <- sig
		},
	})
	defer guest.Close()

	host := NewHostBridge(hostConn)
	defer host.Close()

	// Forward SIGTERM
	if err := host.ForwardSignal(syscall.SIGTERM); err != nil {
		t.Fatalf("Failed to forward signal: %v", err)
	}

	select {
	case sig := <-signalReceived:
		if sig != syscall.SIGTERM {
			t.Errorf("Expected SIGTERM, got %v", sig)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for guest to receive signal")
	}

	// Verify child process terminates from signal
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()

	select {
	case <-waitDone:
		// Child terminated as expected
	case <-time.After(2 * time.Second):
		t.Fatal("Child process did not terminate after signal")
	}
}

func TestGuestToHostExitAndOOMForwarding(t *testing.T) {
	hostConn, guestConn := net.Pipe()
	defer hostConn.Close()
	defer guestConn.Close()

	guest := NewGuestInit(guestConn, GuestInitOpts{})
	defer guest.Close()

	host := NewHostBridge(hostConn)
	defer host.Close()

	// 1. Report Exit
	if err := guest.ReportExit(130); err != nil {
		t.Fatalf("Failed to report exit: %v", err)
	}

	select {
	case code := <-host.ExitChan():
		if code != 130 {
			t.Errorf("Expected exit code 130, got %d", code)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for exit code on host")
	}

	// 2. Report OOM Event
	if err := guest.ReportOOM(999); err != nil {
		t.Fatalf("Failed to report OOM: %v", err)
	}

	select {
	case score := <-host.OOMChan():
		if score != 999 {
			t.Errorf("Expected OOM score 999, got %d", score)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for OOM event on host")
	}
}

func TestWatchdogOnAbruptHostDeath(t *testing.T) {
	hostConn, guestConn := net.Pipe()
	defer guestConn.Close()

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start child process: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	watchdogTriggered := make(chan struct{}, 1)
	guest := NewGuestInit(guestConn, GuestInitOpts{
		HeartbeatTimeout: 500 * time.Millisecond,
		InitialPID:       cmd.Process.Pid,
		OnWatchdogTimeout: func() {
			watchdogTriggered <- struct{}{}
		},
	})
	defer guest.Close()

	// Simulate host abrupt crash (kill -9): host connection drops immediately without sending goodbye
	_ = hostConn.Close()

	select {
	case <-watchdogTriggered:
		// Success: Watchdog triggered due to abrupt connection loss
	case <-time.After(2 * time.Second):
		t.Fatal("Watchdog failed to trigger on abrupt host connection drop")
	}

	if !guest.WatchdogFired() {
		t.Error("guest.WatchdogFired() should be true")
	}

	// Child process should have been terminated
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- cmd.Wait()
	}()

	select {
	case <-waitDone:
		// Child successfully killed
	case <-time.After(2 * time.Second):
		t.Fatal("Child process was not terminated by watchdog")
	}
}

func TestWatchdogOnHeartbeatCeased(t *testing.T) {
	hostConn, guestConn := net.Pipe()
	defer hostConn.Close()
	defer guestConn.Close()

	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start child: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	watchdogTriggered := make(chan struct{}, 1)
	guest := NewGuestInit(guestConn, GuestInitOpts{
		HeartbeatTimeout: 200 * time.Millisecond,
		InitialPID:       cmd.Process.Pid,
		OnWatchdogTimeout: func() {
			watchdogTriggered <- struct{}{}
		},
	})
	defer guest.Close()

	// Host sends one heartbeat, then hangs/stops sending
	if err := WriteFrame(hostConn, Frame{Type: MsgHeartbeat, Payload: 1}); err != nil {
		t.Fatalf("Failed to send initial heartbeat: %v", err)
	}

	select {
	case <-watchdogTriggered:
		// Success: Watchdog fired because heartbeats ceased
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("Watchdog did not fire when heartbeats stopped")
	}
}

func TestHostHeartbeatLoop(t *testing.T) {
	hostConn, guestConn := net.Pipe()
	defer hostConn.Close()
	defer guestConn.Close()

	var heartbeatCount atomic.Int32
	guest := NewGuestInit(guestConn, GuestInitOpts{
		HeartbeatTimeout: 1 * time.Second,
	})
	defer guest.Close()

	host := NewHostBridge(hostConn)
	defer host.Close()

	// Start fast heartbeats for testing (50ms interval)
	host.StartHeartbeat(50 * time.Millisecond)

	// Read ACKs on host or count heartbeats
	time.Sleep(250 * time.Millisecond)

	// Watchdog should NOT have fired because heartbeats were continuously received
	if guest.WatchdogFired() {
		t.Errorf("Watchdog fired unexpectedly while heartbeats were active (count: %d)", heartbeatCount.Load())
	}
}

func TestConcurrentBridgeOperations(t *testing.T) {
	hostConn, guestConn := net.Pipe()
	defer hostConn.Close()
	defer guestConn.Close()

	guest := NewGuestInit(guestConn, GuestInitOpts{
		HeartbeatTimeout: 1 * time.Second,
	})
	defer guest.Close()

	host := NewHostBridge(hostConn)
	defer host.Close()

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Concurrently drain host channels to simulate active host supervisor
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-host.ExitChan():
			case <-host.OOMChan():
			}
		}
	}()

	// Concurrently send signals from host
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = host.ForwardSignal(syscall.SIGHUP)
					time.Sleep(5 * time.Millisecond)
				}
			}
		}()
	}

	// Concurrently send exits and OOMs from guest
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					_ = guest.ReportExit(id)
					_ = guest.ReportOOM(uint32(id))
					time.Sleep(5 * time.Millisecond)
				}
			}
		}(i)
	}

	wg.Wait()
}
