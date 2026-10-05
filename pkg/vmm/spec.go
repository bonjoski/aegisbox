package vmm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// HypervisorSpec encapsulates the full hardware specification for booting a direct MicroVM.
type HypervisorSpec struct {
	Platform       string            `json:"platform"`
	VCPUs          int               `json:"vcpus"`
	MemoryBytes    int64             `json:"memory_bytes"`
	KernelPath     string            `json:"kernel_path,omitempty"`
	InitrdPath     string            `json:"initrd_path,omitempty"`
	RootfsPath     string            `json:"rootfs_path"`
	BootArgs       string            `json:"boot_args"`
	VSockPort      uint32            `json:"vsock_port"`
	WorkspaceShare string            `json:"workspace_share,omitempty"`
	NetworkTap     string            `json:"network_tap,omitempty"`
	ExtraEnv       map[string]string `json:"extra_env,omitempty"`
}

// GenerateSpec synthesizes the platform-specific hypervisor configuration.
func GenerateSpec(cfg VMConfig) (*HypervisorSpec, error) {
	vcpus := cfg.VCPU
	if vcpus <= 0 {
		vcpus = 2
	}
	memMB := cfg.MemoryMB
	if memMB <= 0 {
		memMB = 512
	}

	rootfs := cfg.RootfsPath
	if rootfs == "" {
		// Look for default appliance squashfs
		candidates := []string{
			"build/appliance/appliance.squashfs",
			"appliance/appliance.squashfs",
			filepath.Join(os.Getenv("HOME"), ".aegisbox", "appliance.squashfs"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				rootfs = c
				break
			}
		}
	}

	bootArgs := "console=ttyS0 reboot=k panic=1 pci=off init=/init"
	if runtime.GOOS == "darwin" {
		bootArgs = "console=hvc0 reboot=k panic=1 init=/init"
	}

	spec := &HypervisorSpec{
		Platform:       runtime.GOOS,
		VCPUs:          vcpus,
		MemoryBytes:    int64(memMB) * 1024 * 1024,
		KernelPath:     cfg.KernelPath,
		RootfsPath:     rootfs,
		BootArgs:       bootArgs,
		VSockPort:      1024,
		WorkspaceShare: cfg.WorkspaceMount,
	}

	return spec, nil
}

// DirectHypervisorManager manages raw hypervisor execution across supported host operating systems.
type DirectHypervisorManager struct {
	driver HypervisorDriver
}

// NewDirectHypervisorManager returns a direct manager initialized with the current platform driver.
func NewDirectHypervisorManager() *DirectHypervisorManager {
	return &DirectHypervisorManager{
		driver: NewPlatformDriver(),
	}
}

// PrepareBoot verifies hypervisor prerequisites and prepares the machine specification.
func (m *DirectHypervisorManager) PrepareBoot(ctx context.Context, cfg VMConfig) (*HypervisorSpec, error) {
	if err := m.driver.VerifyPrerequisites(ctx); err != nil {
		return nil, fmt.Errorf("hypervisor hardware validation failed: %w", err)
	}

	spec, err := GenerateSpec(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to generate hypervisor specification: %w", err)
	}

	return spec, nil
}

// ExportFirecrackerConfig serializes the spec into Firecracker REST API format.
func (s *HypervisorSpec) ExportFirecrackerConfig() ([]byte, error) {
	fcConfig := map[string]interface{}{
		"boot-source": map[string]interface{}{
			"kernel_image_path": s.KernelPath,
			"boot_args":         s.BootArgs,
		},
		"drives": []map[string]interface{}{
			{
				"drive_id":     "rootfs",
				"path_on_host": s.RootfsPath,
				"is_root_device": true,
				"is_read_only":   true,
			},
		},
		"machine-config": map[string]interface{}{
			"vcpu_count":  s.VCPUs,
			"mem_size_mib": s.MemoryBytes / (1024 * 1024),
			"smt":         false,
		},
		"vsock": map[string]interface{}{
			"vsock_id":  "vsock0",
			"guest_cid": 3,
			"uds_path":  "/tmp/aegisbox-vsock.sock",
		},
	}

	return json.MarshalIndent(fcConfig, "", "  ")
}

// ExportAppleVZSpec serializes the spec into Apple Virtualization.framework configuration.
func (s *HypervisorSpec) ExportAppleVZSpec() ([]byte, error) {
	vzConfig := map[string]interface{}{
		"platform":       "apple-virtualization-framework",
		"bootloader":     "VZLinuxBootLoader",
		"kernel":         s.KernelPath,
		"command_line":   s.BootArgs,
		"cpu_count":      s.VCPUs,
		"memory_bytes":   s.MemoryBytes,
		"storage_device": s.RootfsPath,
		"socket_device": map[string]interface{}{
			"type": "virtio-vsock",
			"port": s.VSockPort,
		},
		"directory_share": map[string]interface{}{
			"type":      "virtio-fs",
			"tag":       "workspace",
			"host_path": s.WorkspaceShare,
		},
	}

	return json.MarshalIndent(vzConfig, "", "  ")
}
