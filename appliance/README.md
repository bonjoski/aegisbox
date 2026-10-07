# Aegisbox MicroVM Minimal Appliance & Rootfs

This directory contains the source artifacts, build automation, and configurations for generating the minimal microVM appliance image used by **Aegisbox**.

The appliance provides an isolated Linux execution sandbox with sub-second boot times, low memory overhead, and an immutable root filesystem equipped with essential pentesting and agent toolchains.

---

## Deliverables & Components

- [**`init.sh`**](init.sh): The minimal Linux PID 1 initialization and supervisor script for the microVM.
- [**`Dockerfile.alpine`**](Dockerfile.alpine): Multi-stage container recipe compiling the static Go guest daemon and packaging an Alpine Linux rootfs stripped down to under 25MB compressed.
- [**`build-appliance.sh`**](build-appliance.sh): Automated builder producing SquashFS and Initramfs CPIO artifacts and generating validated boot specifications.


---

## Appliance Architecture & Boot Sequence

When the microVM hypervisor boots the guest kernel (`vmlinux`), the kernel mounts the rootfs (or unpacks initramfs) and transfers control to `/init` (PID 1):

```
+-------------------------------------------------------------+
|                     Host Hypervisor                         |
|   (Linux KVM / Firecracker  or  macOS Virtualization.fw)    |
+-------------------------------------------------------------+
         |                         |                    |
    Rootfs (SquashFS/CPIO)    VSOCK Port 1024     VirtioFS / 9p
         |                         |                    |
         v                         v                    v
+-------------------------------------------------------------+
|                  Aegisbox MicroVM Appliance                 |
|                                                             |
| 1. PID 1 (/init):                                           |
|    - Mounts /proc, /sys, /dev, /dev/pts, /dev/shm, /tmp     |
|    - Mounts host workspace -> /workspace (virtiofs/9p)     |
|    - Configures loopback (127.0.0.1) & /dev/vsock nodes     |
|                                                             |
| 2. Guest Daemon (/bin/aegisbox-guest):                      |
|    - Listens on VSOCK/TCP port 1024                         |
|    - Receives JSON ExecutionRequests over stream            |
|    - Executes commands in sanitized environment             |
|    - Reaps children and supervises sandbox lifecycle        |
+-------------------------------------------------------------+
```

### PID 1 Initialization Sequence (`init.sh`)
1. **Virtual Filesystem Setup**: Mounts `/proc` (procfs), `/sys` (sysfs), `/dev` (devtmpfs), `/dev/pts` (devpts for pty allocation), and `/dev/shm` (shared memory).
2. **Device Node Integrity**: Ensures `/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/tty`, and `/dev/console` exist.
3. **Workspace Attachment**: Inspects and mounts host workspace shared via VirtioFS or 9p at `/workspace`.
4. **Networking**: Configures loopback interface (`lo` at `127.0.0.1`) and initialises VSOCK device nodes (`/dev/vsock` major 10, minor 241).
5. **Daemon Supervision**: Launches `/bin/aegisbox-guest -port 1024` and reaps any zombie processes. Traps shutdown signals for clean VM termination.

---

## Building the Appliance

The build script automatically detects the host architecture (`arm64` or `x86_64`) and uses Docker/Podman if available, or falls back to standalone Alpine minirootfs assembly.

### Prerequisites

- **Go 1.24+**: For compiling the static `aegisbox-guest` daemon.
- **SquashFS Tools**: `mksquashfs`
  - macOS: `brew install squashfs`
  - Debian/Ubuntu: `sudo apt-get install -y squashfs-tools`
  - Fedora/RHEL: `sudo dnf install -y squashfs-tools`
- *(Optional)* **Docker / Podman**: For multi-stage container builds.

### Quick Build

Run the builder script directly from the repository root:

```bash
# Build both SquashFS (.squashfs) and Initramfs (.cpio.gz)
./appliance/build-appliance.sh

# Build only SquashFS
./appliance/build-appliance.sh --format squashfs

# Build only Initramfs (cpio.gz)
./appliance/build-appliance.sh --format cpio

# Cross-compile for x86_64 on Apple Silicon host
./appliance/build-appliance.sh --arch x86_64
```

### Build Artifacts

Outputs are saved to `build/appliance/` (with symlinks created in `build/`):

| File | Description | Typical Size |
|---|---|---|
| `build/appliance/appliance.squashfs` | Read-only compressed root filesystem (XZ block compressed) | **~4.1 MB** (Budget: <25 MB) |
| `build/appliance/appliance.cpio.gz` | Gzip-compressed initramfs image bootable directly with kernel | **~5.0 MB** (Budget: <25 MB) |
| `build/appliance/aegisbox-guest` | Statically linked Linux ELF daemon (`CGO_ENABLED=0`) | ~4.9 MB uncompressed |
| `build/appliance/firecracker-config.json` | Sample launch config for Firecracker microVM | Spec file |
| `build/appliance/apple-vz-spec.json` | Sample launch spec for Apple Virtualization.framework | Spec file |

---

## Appliance Toolchain & Utilities

The appliance includes utilities needed for security evaluations and autonomous pentesting tasks while maintaining an ultra-compact footprint:

- **Core Shell**: `busybox`, `bash`
- **Network & Discovery**: `curl`, `nmap`, `bind-tools` (`dig`, `nslookup`), `iproute2`, `iptables`
- **Scripting & Automation**: `python3` (stripped of test suites, IDLE, and doc caches)
- **Version Control**: `git`
- **Aegisbox Daemon**: `/bin/aegisbox-guest` listening on VSOCK port 1024

---

## Kernel Requirements

To boot the minimal appliance rootfs, the guest Linux kernel (`vmlinux` or `bzImage`) must have the following configuration options compiled in (`=y`) or available as modules:

### Virtualization & Hardware Drivers
```ini
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y
CONFIG_VIRTIO_BALLOON=y
CONFIG_VIRTIO_BLK=y
CONFIG_VIRTIO_NET=y
```

### Shared Filesystem Support (Host Workspace)
```ini
# VirtioFS (High Performance Shared Filesystem)
CONFIG_FUSE_FS=y
CONFIG_VIRTIO_FS=y

# 9p (Plan 9 File System fallback)
CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_9P_FS=y
CONFIG_9P_FS_POSIX_ACL=y
CONFIG_9P_FS_SECURITY=y
```

### VSOCK Communication
```ini
CONFIG_VSOCKETS=y
CONFIG_VSOCKETS_DIAG=y
CONFIG_VIRTIO_VSOCKETS=y
CONFIG_VIRTIO_VSOCKETS_COMMON=y
```

### Root Filesystem Formats
```ini
# SquashFS Support
CONFIG_SQUASHFS=y
CONFIG_SQUASHFS_FILE_DIRECT=y
CONFIG_SQUASHFS_DECOMP_MULTI_PERCPU=y
CONFIG_SQUASHFS_XATTR=y
CONFIG_SQUASHFS_XZ=y

# Initramfs / CPIO Support
CONFIG_BLK_DEV_INITRD=y
CONFIG_RD_GZIP=y
CONFIG_RD_XZ=y
```

---

## Runtime Mount Configuration

### 1. Firecracker (Linux KVM)

Configure the root drive and kernel boot parameters via Firecracker API:

```json
{
  "boot-source": {
    "kernel_image_path": "vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/init root=/dev/vda ro"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "build/appliance/appliance.squashfs",
      "is_root_device": true,
      "is_read_only": true
    }
  ],
  "machine-config": {
    "vcpu_count": 1,
    "mem_size_mib": 256
  },
  "vsock": {
    "guest_cid": 3,
    "uds_path": "/tmp/aegisbox.vsock"
  }
}
```

### 2. Apple Virtualization.framework (macOS Apple VZ)

Using macOS Swift or Go VZ bindings:

1. **Bootloader**:
   - `VZLinuxBootLoader(kernelURL: vmlinuxURL)`
   - `commandLine = "console=hvc0 init=/init root=/dev/vda ro"`
   - `initialRamdiskURL = appliance.cpio.gz` *(optional if using initramfs boot)*
2. **Root Disk**:
   - `VZDiskImageStorageDeviceAttachment(url: appliance.squashfs, readOnly: true)`
   - Attached as `VZVirtioBlockDeviceConfiguration` (`/dev/vda`)
3. **Workspace Mount**:
   - `VZVirtioFileSystemDeviceConfiguration(tag: "workspace")`
   - Maps host directory to `/workspace`
4. **VSOCK Connection**:
   - `VZVirtioSocketDeviceConfiguration` forwarding port 1024 to host socket.

---

## Guest Daemon RPC Protocol

The host communicates with `/bin/aegisbox-guest` over VSOCK port 1024 using newline-delimited JSON.

### Request Payload (`ExecutionRequest`)
```json
{
  "command": "python3 -c 'import sys; print(sys.version)'",
  "env": {
    "CUSTOM_ENV": "value"
  },
  "work_dir": "/workspace",
  "timeout": 15000000000
}
```

### Response Payload (`ExecutionResult`)
```json
{
  "stdout": "3.12.6 (main, Sep  6 2024, 11:37:29)\n",
  "stderr": "",
  "exit_code": 0,
  "error": ""
}
```

---

## Security & Isolation Guarantees

1. **Immutable Rootfs**: Root filesystem is mounted strictly read-only (`ro`). Any ephemeral writes are constrained to tmpfs (`/tmp`, `/run`).
2. **Workspace Encapsulation**: Host files are mounted exclusively at `/workspace` with explicit boundary checks.
3. **Clean Environment Execution**: The guest daemon sanitizes execution environment variables and prevents host secret leakage.
4. **Zombie Process Reaping**: PID 1 `init.sh` automatically reaps orphaned process trees spawned by agent commands, preventing kernel PID exhaustion.
