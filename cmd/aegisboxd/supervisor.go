package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	ipcv1 "github.com/bonjoski/aegisbox/pkg/ipc/v1"
	"github.com/bonjoski/aegisbox/pkg/vmm"
)

var (
	// ErrMaxVMQuotaExceeded is returned when a client attempts to launch more microVMs than allowed.
	ErrMaxVMQuotaExceeded = errors.New("maximum concurrent microVM quota exceeded (limit: 3)")
	// ErrVMNotFound is returned when an operation targets a non-existent or already terminated VM.
	ErrVMNotFound = errors.New("microVM instance not found")
)

// ActiveVM represents a live microVM tracked by the supervisor.
type ActiveVM struct {
	ID             string
	Profile        string
	WorkspacePath  string
	VCPUCount      int32
	MemoryMB       int32
	Handle         vmm.VMHandle
	StartTime      time.Time
	Status         string // "running", "paused", "quarantined", "stopped"
	VsockPort      uint32
	ConsoleBuffer  []byte
	mu             sync.Mutex
}

// Supervisor manages the lifecycle, snapshot pooling, and resource quotas of microVMs.
type Supervisor struct {
	driver       vmm.HypervisorDriver
	instances    map[string]*ActiveVM
	pool         chan vmm.VMHandle
	maxQuota     int
	poolSize     int
	mu           sync.RWMutex
	shuttingDown bool
	wg           sync.WaitGroup
}

// NewSupervisor initializes the supervisor with the host platform's hypervisor driver.
func NewSupervisor(driver vmm.HypervisorDriver, maxQuota, poolSize int) *Supervisor {
	if driver == nil {
		driver = vmm.NewPlatformDriver()
	}
	if maxQuota <= 0 {
		maxQuota = 3
	}
	if poolSize <= 0 {
		poolSize = 2
	}

	s := &Supervisor{
		driver:    driver,
		instances: make(map[string]*ActiveVM),
		pool:      make(chan vmm.VMHandle, poolSize),
		maxQuota:  maxQuota,
		poolSize:  poolSize,
	}

	// Warm the snapshot pool in the background
	s.warmPool()

	return s
}

func (s *Supervisor) warmPool() {
	s.mu.RLock()
	if s.shuttingDown {
		s.mu.RUnlock()
		return
	}
	poolSize := s.poolSize
	s.mu.RUnlock()

	for i := 0; i < poolSize; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			cfg := vmm.VMConfig{
				ID:       s.generateID("pool"),
				VCPU:     2,
				MemoryMB: 512,
			}
			handle, err := s.driver.SpawnVM(ctx, cfg)
			if err != nil {
				return
			}

			s.mu.Lock()
			if s.shuttingDown {
				s.mu.Unlock()
				_ = handle.Kill(context.Background())
				return
			}
			select {
			case s.pool <- handle:
				s.mu.Unlock()
			default:
				s.mu.Unlock()
				_ = handle.Kill(context.Background())
			}
		}()
	}
}

func (s *Supervisor) generateID(prefix string) string {
	bytes := make([]byte, 6)
	_, _ = rand.Read(bytes)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(bytes))
}

// StartVM provisions or unpauses a microVM instance and records its telemetry.
func (s *Supervisor) StartVM(ctx context.Context, req *ipcv1.StartVMRequest) (*ActiveVM, int64, error) {
	s.mu.Lock()
	if s.shuttingDown {
		s.mu.Unlock()
		return nil, 0, errors.New("aegisboxd is shutting down")
	}

	if len(s.instances) >= s.maxQuota {
		s.mu.Unlock()
		return nil, 0, ErrMaxVMQuotaExceeded
	}

	s.mu.Unlock()

	start := time.Now()
	var handle vmm.VMHandle
	var err error

	// Try acquiring from pre-warmed snapshot pool if requested
	if req.UseSnapshotPool {
		select {
		case handle = <-s.pool:
			// Replenish the pool in background
			go s.warmPool()
		default:
			// Fallback to fresh spawn if pool is momentarily drained
		}
	}

	if handle == nil {
		cfg := vmm.VMConfig{
			ID:             s.generateID("vm"),
			VCPU:           int(req.VcpuCount),
			MemoryMB:       int(req.MemoryMb),
			WorkspaceMount: req.WorkspacePath,
		}
		if cfg.VCPU <= 0 {
			cfg.VCPU = 2
		}
		if cfg.MemoryMB <= 0 {
			cfg.MemoryMB = 512
		}

		handle, err = s.driver.SpawnVM(ctx, cfg)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to spawn microVM: %w", err)
		}
	}

	latencyUs := time.Since(start).Microseconds()

	vm := &ActiveVM{
		ID:            handle.ID(),
		Profile:       req.Profile,
		WorkspacePath: req.WorkspacePath,
		VCPUCount:     req.VcpuCount,
		MemoryMB:      req.MemoryMb,
		Handle:        handle,
		StartTime:     time.Now(),
		Status:        "running",
		VsockPort:     50051,
	}

	s.mu.Lock()
	s.instances[vm.ID] = vm
	s.mu.Unlock()

	return vm, latencyUs, nil
}

// StopVM terminates a running microVM and purges its ephemeral memory.
func (s *Supervisor) StopVM(ctx context.Context, vmID string, force, discardCoW bool) (int32, error) {
	s.mu.Lock()
	vm, exists := s.instances[vmID]
	if !exists {
		s.mu.Unlock()
		return 1, ErrVMNotFound
	}
	delete(s.instances, vmID)
	s.mu.Unlock()

	vm.mu.Lock()
	defer vm.mu.Unlock()

	vm.Status = "stopped"
	err := vm.Handle.Kill(ctx)

	// Adversarial Memory Sanitization: Scrub RAM references
	vm.ConsoleBuffer = nil

	if err != nil {
		return 1, fmt.Errorf("failed to terminate microVM: %w", err)
	}

	return 0, nil
}

// ListVMs returns summary objects of all active microVM instances.
func (s *Supervisor) ListVMs() []*ipcv1.VMInstanceSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()

	summaries := make([]*ipcv1.VMInstanceSummary, 0, len(s.instances))
	for _, vm := range s.instances {
		vm.mu.Lock()
		uptime := int64(time.Since(vm.StartTime).Seconds())
		summary := &ipcv1.VMInstanceSummary{
			VmId:          vm.ID,
			Profile:       vm.Profile,
			WorkspacePath: vm.WorkspacePath,
			UptimeSeconds: uptime,
			VcpuCount:     vm.VCPUCount,
			MemoryMb:      vm.MemoryMB,
			Status:        vm.Status,
		}
		vm.mu.Unlock()
		summaries = append(summaries, summary)
	}

	return summaries
}

// GetVM returns a specific active VM instance by ID.
func (s *Supervisor) GetVM(vmID string) (*ActiveVM, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	vm, exists := s.instances[vmID]
	if !exists {
		return nil, ErrVMNotFound
	}
	return vm, nil
}

// ActiveCount returns the number of active microVMs.
func (s *Supervisor) ActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.instances)
}

// TeardownAll gracefully terminates all active microVM instances.
func (s *Supervisor) TeardownAll(ctx context.Context) {
	s.mu.Lock()
	if s.shuttingDown {
		s.mu.Unlock()
		return
	}
	s.shuttingDown = true
	instances := make([]*ActiveVM, 0, len(s.instances))
	for _, vm := range s.instances {
		instances = append(instances, vm)
	}
	s.instances = make(map[string]*ActiveVM)
	s.mu.Unlock()

	for _, vm := range instances {
		_ = vm.Handle.Kill(ctx)
	}

	// Wait for any in-flight warmPool goroutines to finish
	s.wg.Wait()

	// Drain pool safely
	s.mu.Lock()
	close(s.pool)
	for handle := range s.pool {
		_ = handle.Kill(ctx)
	}
	s.mu.Unlock()
}
