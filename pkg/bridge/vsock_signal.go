package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DefaultHeartbeatInterval is the standard frequency host pings guest (1 second).
const DefaultHeartbeatInterval = 1 * time.Second

// DefaultWatchdogTimeout is the maximum duration guest waits for a heartbeat before killing child processes (2 seconds).
const DefaultWatchdogTimeout = 2 * time.Second

// HostBridge manages host-side signal trapping, heartbeat transmission, and guest event reception.
type HostBridge struct {
	conn       io.ReadWriteCloser
	writeMu    sync.Mutex
	sigChan    chan os.Signal
	exitChan   chan int
	oomChan    chan uint32
	errChan    chan error
	done       chan struct{}
	closeOnce  sync.Once
	wg         sync.WaitGroup
	heartbeatSeq uint32
	closed     atomic.Bool
}

// NewHostBridge creates a HostBridge using an established connection to the guest.
func NewHostBridge(conn io.ReadWriteCloser) *HostBridge {
	hb := &HostBridge{
		conn:     conn,
		sigChan:  make(chan os.Signal, 8),
		exitChan: make(chan int, 8),
		oomChan:  make(chan uint32, 8),
		errChan:  make(chan error, 8),
		done:     make(chan struct{}),
	}

	hb.wg.Add(1)
	go hb.readLoop()

	return hb
}

// DialHostBridge dials the guest at the given address and returns a HostBridge.
func DialHostBridge(ctx context.Context, network, addr string) (*HostBridge, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial guest vsock signal endpoint %s: %w", addr, err)
	}
	return NewHostBridge(conn), nil
}

// StartSignalTrap registers host signal handlers for SIGINT, SIGTERM, SIGHUP (or custom signals)
// and automatically transmits them to the microVM guest.
func (hb *HostBridge) StartSignalTrap(signals ...os.Signal) {
	if len(signals) == 0 {
		signals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP}
	}

	signal.Notify(hb.sigChan, signals...)

	hb.wg.Add(1)
	go func() {
		defer hb.wg.Done()
		for {
			select {
			case <-hb.done:
				return
			case sig, ok := <-hb.sigChan:
				if !ok {
					return
				}
				_ = hb.ForwardSignal(sig)
			}
		}
	}()
}

// StartHeartbeat begins sending keepalive frames to the guest at the specified interval (defaults to 1s).
func (hb *HostBridge) StartHeartbeat(interval time.Duration) {
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}

	hb.wg.Add(1)
	go func() {
		defer hb.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-hb.done:
				return
			case <-ticker.C:
				seq := atomic.AddUint32(&hb.heartbeatSeq, 1)
				if err := hb.writeFrame(Frame{Type: MsgHeartbeat, Payload: seq}); err != nil {
					if !hb.closed.Load() {
						select {
						case hb.errChan <- fmt.Errorf("heartbeat send failed: %w", err):
						default:
						}
					}
					return
				}
			}
		}
	}()
}

// ForwardSignal transmits a single signal frame to the guest.
func (hb *HostBridge) ForwardSignal(sig os.Signal) error {
	payload, err := SignalToPayload(sig)
	if err != nil {
		return err
	}
	return hb.writeFrame(Frame{
		Type:    MsgSignal,
		Payload: payload,
	})
}

func (hb *HostBridge) writeFrame(f Frame) error {
	if hb.closed.Load() {
		return errors.New("host bridge is closed")
	}

	hb.writeMu.Lock()
	defer hb.writeMu.Unlock()

	return WriteFrame(hb.conn, f)
}

func (hb *HostBridge) readLoop() {
	defer hb.wg.Done()

	for {
		frame, err := ReadFrame(hb.conn)
		if err != nil {
			if !hb.closed.Load() && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				select {
				case hb.errChan <- fmt.Errorf("vsock read error: %w", err):
				default:
				}
			}
			return
		}

		switch frame.Type {
		case MsgExit:
			exitCode := PayloadToExitCode(frame.Payload)
			select {
			case hb.exitChan <- exitCode:
			default:
				// Channel buffer full: discard oldest and store newest to avoid deadlocking readLoop
				select {
				case <-hb.exitChan:
				default:
				}
				select {
				case hb.exitChan <- exitCode:
				default:
				}
			}
		case MsgOOM:
			select {
			case hb.oomChan <- frame.Payload:
			default:
				select {
				case <-hb.oomChan:
				default:
				}
				select {
				case hb.oomChan <- frame.Payload:
				default:
				}
			}
		case MsgHeartbeatAck:
			// Heartbeat ACK received from guest
		default:
			// Ignore unrecognized frames gracefully
		}
	}
}

// ExitChan returns the channel receiving exit code notifications from guest.
func (hb *HostBridge) ExitChan() <-chan int {
	return hb.exitChan
}

// OOMChan returns the channel receiving OOM killer events from guest.
func (hb *HostBridge) OOMChan() <-chan uint32 {
	return hb.oomChan
}

// ErrChan returns the channel receiving unexpected connection or bridge errors.
func (hb *HostBridge) ErrChan() <-chan error {
	return hb.errChan
}

// Close terminates signal trapping, closes the vsock connection, and waits for background routines.
func (hb *HostBridge) Close() error {
	var closeErr error
	hb.closeOnce.Do(func() {
		hb.closed.Store(true)
		signal.Stop(hb.sigChan)
		close(hb.done)
		closeErr = hb.conn.Close()
		hb.wg.Wait()
		close(hb.exitChan)
		close(hb.oomChan)
		close(hb.errChan)
	})
	return closeErr
}

// GuestInitOpts configures behavior for the in-guest signal supervisor.
type GuestInitOpts struct {
	HeartbeatTimeout   time.Duration
	OnWatchdogTimeout  func()
	OnSignalReceived   func(sig syscall.Signal)
	InitialPGID        int
	InitialPID         int
}

// GuestInit manages signal dispatch to child process groups, responds to heartbeats,
// and enforces a watchdog that terminates child processes if the host abruptly dies.
type GuestInit struct {
	conn             io.ReadWriteCloser
	opts             GuestInitOpts
	writeMu          sync.Mutex
	procMu           sync.RWMutex
	targetPGID       int
	targetPID        int
	heartbeatReset   chan struct{}
	done             chan struct{}
	closeOnce        sync.Once
	wg               sync.WaitGroup
	closed           atomic.Bool
	watchdogFired    atomic.Bool
}

// NewGuestInit initializes the in-guest signal handler and watchdog over the given vsock connection.
func NewGuestInit(conn io.ReadWriteCloser, opts GuestInitOpts) *GuestInit {
	if opts.HeartbeatTimeout <= 0 {
		opts.HeartbeatTimeout = DefaultWatchdogTimeout
	}

	gi := &GuestInit{
		conn:           conn,
		opts:           opts,
		targetPGID:     opts.InitialPGID,
		targetPID:      opts.InitialPID,
		heartbeatReset: make(chan struct{}, 1),
		done:           make(chan struct{}),
	}

	gi.wg.Add(2)
	go gi.readLoop()
	go gi.watchdogLoop()

	return gi
}

// SetTargetProcess updates the active child process group and PID being supervised.
func (gi *GuestInit) SetTargetProcess(pgid, pid int) {
	gi.procMu.Lock()
	defer gi.procMu.Unlock()
	gi.targetPGID = pgid
	gi.targetPID = pid
}

// ReportExit transmits the child process exit code back to the host.
func (gi *GuestInit) ReportExit(exitCode int) error {
	return gi.writeFrame(Frame{
		Type:    MsgExit,
		Payload: ExitCodeToPayload(exitCode),
	})
}

// ReportOOM transmits an OOM killer event back to the host.
func (gi *GuestInit) ReportOOM(score uint32) error {
	return gi.writeFrame(Frame{
		Type:    MsgOOM,
		Payload: score,
	})
}

// WatchdogFired reports whether the heartbeat watchdog triggered due to host disappearance.
func (gi *GuestInit) WatchdogFired() bool {
	return gi.watchdogFired.Load()
}

func (gi *GuestInit) writeFrame(f Frame) error {
	if gi.closed.Load() {
		return errors.New("guest init bridge is closed")
	}

	gi.writeMu.Lock()
	defer gi.writeMu.Unlock()

	return WriteFrame(gi.conn, f)
}

func (gi *GuestInit) readLoop() {
	defer gi.wg.Done()

	for {
		frame, err := ReadFrame(gi.conn)
		if err != nil {
			if !gi.closed.Load() {
				// Abrupt disconnection: host died or was killed (SIGKILL / crash)
				gi.triggerWatchdog("vsock connection dropped unexpectedly")
			}
			return
		}

		switch frame.Type {
		case MsgSignal:
			sig := PayloadToSignal(frame.Payload)
			gi.dispatchSignal(sig)
		case MsgHeartbeat:
			// Reset watchdog timer
			select {
			case gi.heartbeatReset <- struct{}{}:
			default:
			}
			// Send ACK back to host
			_ = gi.writeFrame(Frame{
				Type:    MsgHeartbeatAck,
				Payload: frame.Payload,
			})
		default:
			// Ignore unknown frames
		}
	}
}

func (gi *GuestInit) watchdogLoop() {
	defer gi.wg.Done()

	timer := time.NewTimer(gi.opts.HeartbeatTimeout)
	defer timer.Stop()

	for {
		select {
		case <-gi.done:
			return
		case <-gi.heartbeatReset:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(gi.opts.HeartbeatTimeout)
		case <-timer.C:
			// Watchdog triggered: no heartbeat received within timeout
			gi.triggerWatchdog("watchdog timeout: no heartbeat received from host")
			return
		}
	}
}

func (gi *GuestInit) dispatchSignal(sig syscall.Signal) {
	gi.procMu.RLock()
	pgid := gi.targetPGID
	pid := gi.targetPID
	gi.procMu.RUnlock()

	_ = killProcessGroup(pgid, pid, sig)

	if gi.opts.OnSignalReceived != nil {
		gi.opts.OnSignalReceived(sig)
	}
}

func (gi *GuestInit) triggerWatchdog(reason string) {
	if !gi.watchdogFired.CompareAndSwap(false, true) {
		return
	}

	// Clean kill child processes: SIGTERM first, then SIGKILL
	gi.procMu.RLock()
	pgid := gi.targetPGID
	pid := gi.targetPID
	gi.procMu.RUnlock()

	if pgid > 0 || pid > 0 {
		_ = killProcessGroup(pgid, pid, syscall.SIGTERM)
		time.Sleep(50 * time.Millisecond)
		_ = killProcessGroup(pgid, pid, syscall.SIGKILL)
	}

	if gi.opts.OnWatchdogTimeout != nil {
		gi.opts.OnWatchdogTimeout()
	}
}

// Close shuts down the guest init handler and cleans up resources.
func (gi *GuestInit) Close() error {
	var closeErr error
	gi.closeOnce.Do(func() {
		gi.closed.Store(true)
		close(gi.done)
		closeErr = gi.conn.Close()
		gi.wg.Wait()
	})
	return closeErr
}
