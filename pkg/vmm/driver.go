package vmm

import (
	"context"
	"fmt"
	"io"
	"time"
)

// VMConfig specifies hardware resources and containment settings for a microVM.
type VMConfig struct {
	ID             string        `json:"id"`
	VCPU           int           `json:"vcpu"`
	MemoryMB       int           `json:"memory_mb"`
	KernelPath     string        `json:"kernel_path"`
	RootfsPath     string        `json:"rootfs_path"`
	WorkspaceMount string        `json:"workspace_mount"`
	TargetHost     string        `json:"target_host,omitempty"`
	TargetPorts    []int         `json:"target_ports,omitempty"`
	Timeout        time.Duration `json:"timeout,omitempty"`
}

// ProcessExitStatus represents the outcome of an execution inside the microVM.
type ProcessExitStatus struct {
	ExitCode int           `json:"exit_code"`
	Duration time.Duration `json:"duration"`
	ErrorMsg string        `json:"error_msg,omitempty"`
}

// VMHandle represents an active, isolated microVM instance.
type VMHandle interface {
	ID() string
	VSockStream(ctx context.Context, port uint32) (io.ReadWriteCloser, error)
	Kill(ctx context.Context) error
	Wait(ctx context.Context) (*ProcessExitStatus, error)
}

// HypervisorDriver is the abstraction layer over platform-specific hypervisors.
type HypervisorDriver interface {
	Name() string
	VerifyPrerequisites(ctx context.Context) error
	SpawnVM(ctx context.Context, cfg VMConfig) (VMHandle, error)
	Teardown(ctx context.Context, handle VMHandle) error
}

// ErrHypervisorNotSupported is returned when the current host lacks required virtualization primitives.
type ErrHypervisorNotSupported struct {
	Reason string
}

func (e *ErrHypervisorNotSupported) Error() string {
	return fmt.Sprintf("hypervisor not supported on this host: %s", e.Reason)
}

// NewPlatformDriver returns the appropriate hypervisor driver for the host platform.
func NewPlatformDriver() HypervisorDriver {
	return newPlatformDriver()
}

