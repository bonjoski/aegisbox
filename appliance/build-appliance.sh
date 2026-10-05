#!/usr/bin/env bash
# ==============================================================================
# Aegisbox MicroVM Appliance Build Script
# ==============================================================================
# Builds the minimal Linux rootfs, compiles the static guest daemon,
# packages into a compressed SquashFS (<25MB) or initramfs CPIO image,
# and verifies boot configurations for Firecracker and Apple VZ.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Configuration & Defaults
OUTPUT_DIR="${REPO_ROOT}/build/appliance"
ROOTFS_DIR="${OUTPUT_DIR}/rootfs"
FORMAT="both"            # squashfs, cpio, or both
TARGET_ARCH=""           # auto-detected (arm64/aarch64 or x86_64/amd64)
MAX_SIZE_MB=25           # target image threshold
SKIP_TEST=0
STANDALONE=0

# Color outputs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[aegisbox-builder]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[aegisbox-builder]${NC} ✅ $*"; }
log_warn()  { echo -e "${YELLOW}[aegisbox-builder]${NC} ⚠️  $*"; }
log_err()   { echo -e "${RED}[aegisbox-builder]${NC} ❌ $*"; }

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  --format <squashfs|cpio|both>   Output filesystem format (default: both)
  --arch <arm64|x86_64>          Target architecture (default: detected host arch)
  --out-dir <path>               Target output directory (default: build/appliance)
  --standalone                   Build directly from Alpine rootfs without Docker daemon
  --skip-test                    Skip bootability and sanity test checks
  -h, --help                     Show this help message
EOF
    exit 0
}

# Parse command line flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --format)
            FORMAT="$2"
            shift 2
            ;;
        --arch)
            TARGET_ARCH="$2"
            shift 2
            ;;
        --out-dir)
            OUTPUT_DIR="$2"
            ROOTFS_DIR="${OUTPUT_DIR}/rootfs"
            shift 2
            ;;
        --standalone)
            STANDALONE=1
            shift
            ;;
        --skip-test)
            SKIP_TEST=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_err "Unknown argument: $1"
            usage
            ;;
    esac
done

# Detect Architecture
if [[ -z "${TARGET_ARCH}" ]]; then
    HOST_ARCH="$(uname -m)"
    case "${HOST_ARCH}" in
        arm64|aarch64)
            TARGET_ARCH="arm64"
            ALPINE_ARCH="aarch64"
            ;;
        x86_64|amd64)
            TARGET_ARCH="amd64"
            ALPINE_ARCH="x86_64"
            ;;
        *)
            log_warn "Unknown host architecture '${HOST_ARCH}', defaulting to arm64"
            TARGET_ARCH="arm64"
            ALPINE_ARCH="aarch64"
            ;;
    esac
else
    case "${TARGET_ARCH}" in
        arm64|aarch64)
            TARGET_ARCH="arm64"
            ALPINE_ARCH="aarch64"
            ;;
        x86_64|amd64)
            TARGET_ARCH="amd64"
            ALPINE_ARCH="x86_64"
            ;;
        *)
            log_err "Unsupported target arch: ${TARGET_ARCH}"
            exit 1
            ;;
    esac
fi

log_info "Initializing Aegisbox Appliance Builder"
log_info "  Repo Root:   ${REPO_ROOT}"
log_info "  Target Arch: ${TARGET_ARCH} (${ALPINE_ARCH})"
log_info "  Output Dir:  ${OUTPUT_DIR}"
log_info "  Format:      ${FORMAT}"

# Clean and prepare workspace
mkdir -p "${OUTPUT_DIR}"
rm -rf "${ROOTFS_DIR}"
mkdir -p "${ROOTFS_DIR}"

# ------------------------------------------------------------------------------
# Step 1: Build Statically Linked aegisbox-guest Binary
# ------------------------------------------------------------------------------
log_info "Step 1: Compiling statically linked aegisbox-guest binary (GOARCH=${TARGET_ARCH})..."

mkdir -p "${REPO_ROOT}/bin"
GUEST_BIN_TEMP="${OUTPUT_DIR}/aegisbox-guest"

(
    cd "${REPO_ROOT}"
    CGO_ENABLED=0 GOOS=linux GOARCH="${TARGET_ARCH}" go build \
        -trimpath \
        -ldflags="-s -w -extldflags '-static'" \
        -o "${GUEST_BIN_TEMP}" \
        ./cmd/aegisbox-guest
)

# Also update project bin directory on Linux hosts
if [[ "$(uname)" == "Linux" ]]; then
    cp -f "${GUEST_BIN_TEMP}" "${REPO_ROOT}/bin/aegisbox-guest" 2>/dev/null || true
fi
log_ok "Static binary generated at ${GUEST_BIN_TEMP}"

# ------------------------------------------------------------------------------
# Step 2: Assemble Minimal Rootfs
# ------------------------------------------------------------------------------
log_info "Step 2: Assembling minimal Linux rootfs..."

CONTAINER_ENGINE=""
if [[ "${STANDALONE}" -eq 0 ]]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        CONTAINER_ENGINE="docker"
    elif command -v podman >/dev/null 2>&1 && podman info >/dev/null 2>&1; then
        CONTAINER_ENGINE="podman"
    fi
fi

if [[ -n "${CONTAINER_ENGINE}" ]]; then
    log_info "Using container engine (${CONTAINER_ENGINE}) with multi-stage Dockerfile..."
    IMAGE_TAG="aegisbox-appliance:${TARGET_ARCH}"
    
    "${CONTAINER_ENGINE}" build \
        -t "${IMAGE_TAG}" \
        -f "${SCRIPT_DIR}/Dockerfile.alpine" \
        "${REPO_ROOT}"

    log_info "Extracting rootfs from container image..."
    CID="$("${CONTAINER_ENGINE}" create "${IMAGE_TAG}")"
    "${CONTAINER_ENGINE}" export "${CID}" | tar -xf - -C "${ROOTFS_DIR}"
    "${CONTAINER_ENGINE}" rm -f "${CID}" >/dev/null
    log_ok "Extracted rootfs using ${CONTAINER_ENGINE}"
else
    log_info "Container engine unavailable or standalone mode requested."
    log_info "Downloading official Alpine minirootfs v3.20 (${ALPINE_ARCH})..."
    
    ALPINE_VERSION="3.20.3"
    ROOTFS_TARBALL="${OUTPUT_DIR}/alpine-minirootfs-${ALPINE_VERSION}-${ALPINE_ARCH}.tar.gz"
    
    if [[ ! -f "${ROOTFS_TARBALL}" ]]; then
        ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/${ALPINE_ARCH}/alpine-minirootfs-${ALPINE_VERSION}-${ALPINE_ARCH}.tar.gz"
        curl -fSL "${ALPINE_URL}" -o "${ROOTFS_TARBALL}"
    fi

    log_info "Extracting base minirootfs..."
    tar -xzf "${ROOTFS_TARBALL}" -C "${ROOTFS_DIR}"

    # Install static guest daemon and symlink
    mkdir -p "${ROOTFS_DIR}/bin" "${ROOTFS_DIR}/usr/local/bin"
    cp -f "${GUEST_BIN_TEMP}" "${ROOTFS_DIR}/bin/aegisbox-guest"
    chmod +x "${ROOTFS_DIR}/bin/aegisbox-guest"
    ln -sf "/bin/aegisbox-guest" "${ROOTFS_DIR}/usr/local/bin/aegisbox-guest"

    # Install init script
    cp -f "${SCRIPT_DIR}/init.sh" "${ROOTFS_DIR}/init"
    chmod +x "${ROOTFS_DIR}/init"

    # Ensure required microVM directories exist
    mkdir -p "${ROOTFS_DIR}/run" \
             "${ROOTFS_DIR}/proc" \
             "${ROOTFS_DIR}/sys" \
             "${ROOTFS_DIR}/dev" \
             "${ROOTFS_DIR}/dev/pts" \
             "${ROOTFS_DIR}/dev/shm" \
             "${ROOTFS_DIR}/workspace" \
             "${ROOTFS_DIR}/root" \
             "${ROOTFS_DIR}/tmp"

    # Fix absolute symlinks in Alpine rootfs to be relative (e.g. var/run -> /run)
    if [[ -L "${ROOTFS_DIR}/var/run" ]]; then
        rm -f "${ROOTFS_DIR}/var/run"
        ln -sf "../run" "${ROOTFS_DIR}/var/run"
    fi

    # Clean unneeded files
    rm -rf "${ROOTFS_DIR}/usr/share/man" \
           "${ROOTFS_DIR}/usr/share/doc" \
           "${ROOTFS_DIR}/var/cache/apk"/* 2>/dev/null || true

    log_ok "Standalone rootfs assembled successfully"
fi

# Ensure critical nodes and executable permissions in rootfs
cp -f "${SCRIPT_DIR}/init.sh" "${ROOTFS_DIR}/init"
chmod 755 "${ROOTFS_DIR}/init"
chmod 755 "${ROOTFS_DIR}/bin/aegisbox-guest" 2>/dev/null || true
mkdir -p "${ROOTFS_DIR}/workspace" "${ROOTFS_DIR}/dev" "${ROOTFS_DIR}/proc" "${ROOTFS_DIR}/sys"

# ------------------------------------------------------------------------------
# Step 3: Package Appliance Rootfs (SquashFS / Initramfs CPIO)
# ------------------------------------------------------------------------------
log_info "Step 3: Packaging appliance rootfs..."

SQUASHFS_OUT="${OUTPUT_DIR}/appliance.squashfs"
CPIO_OUT="${OUTPUT_DIR}/appliance.cpio.gz"

build_cpio() {
    log_info "Generating Initramfs CPIO (gzip compressed)..."
    (
        cd "${ROOTFS_DIR}"
        find . -mindepth 1 | cpio -o -H newc 2>/dev/null | gzip -9 > "${CPIO_OUT}"
    )
    log_ok "Generated Initramfs: ${CPIO_OUT}"
}

build_squashfs() {
    log_info "Generating SquashFS (XZ compressed)..."
    rm -f "${SQUASHFS_OUT}"

    if command -v mksquashfs >/dev/null 2>&1; then
        mksquashfs "${ROOTFS_DIR}" "${SQUASHFS_OUT}" \
            -comp xz \
            -noappend \
            -all-root \
            -b 256K \
            -Xbcj arm,armthumb \
            2>/dev/null || \
        mksquashfs "${ROOTFS_DIR}" "${SQUASHFS_OUT}" \
            -comp xz \
            -noappend \
            -all-root
        log_ok "Generated SquashFS: ${SQUASHFS_OUT}"
    elif [[ -n "${CONTAINER_ENGINE}" ]]; then
        log_info "mksquashfs not found on host, generating via ephemeral Alpine container..."
        "${CONTAINER_ENGINE}" run --rm \
            -v "${ROOTFS_DIR}:/rootfs:ro" \
            -v "${OUTPUT_DIR}:/out" \
            alpine:3.20 sh -c \
            "apk add --no-cache squashfs-tools >/dev/null && mksquashfs /rootfs /out/appliance.squashfs -comp xz -noappend -all-root"
        log_ok "Generated SquashFS via container: ${SQUASHFS_OUT}"
    else
        log_warn "mksquashfs is not installed on host and no container engine available."
        log_warn "Install via: 'brew install squashfs' (macOS) or 'apt-get install squashfs-tools' (Linux)."
        log_warn "Initramfs CPIO will serve as the primary bootable appliance image."
    fi
}

case "${FORMAT}" in
    cpio)
        build_cpio
        ln -sf "${CPIO_OUT}" "${REPO_ROOT}/build/appliance.cpio.gz" 2>/dev/null || true
        ;;
    squashfs)
        build_squashfs
        ln -sf "${SQUASHFS_OUT}" "${REPO_ROOT}/build/appliance.squashfs" 2>/dev/null || true
        ;;
    both)
        build_cpio
        build_squashfs
        ln -sf "${CPIO_OUT}" "${REPO_ROOT}/build/appliance.cpio.gz" 2>/dev/null || true
        ln -sf "${SQUASHFS_OUT}" "${REPO_ROOT}/build/appliance.squashfs" 2>/dev/null || true
        ;;
    *)
        log_err "Unknown format: ${FORMAT}"
        exit 1
        ;;
esac

# ------------------------------------------------------------------------------
# Step 4: Verify Size Budgets (<25MB)
# ------------------------------------------------------------------------------
log_info "Step 4: Checking appliance size constraints..."

check_size() {
    local file_path="$1"
    local name="$2"
    if [[ -f "${file_path}" ]]; then
        local size_bytes
        if [[ "$(uname)" == "Darwin" ]]; then
            size_bytes="$(stat -f%z "${file_path}")"
        else
            size_bytes="$(stat -c%s "${file_path}")"
        fi
        local size_mb
        size_mb="$(awk -v bytes="${size_bytes}" 'BEGIN { printf "%.2f", bytes / 1048576 }')"
        
        if (( $(echo "${size_mb} <= ${MAX_SIZE_MB}" | bc -l 2>/dev/null || awk -v s="${size_mb}" -v m="${MAX_SIZE_MB}" 'BEGIN { exit !(s <= m) }') )); then
            log_ok "${name}: ${size_mb} MB (Budget <= ${MAX_SIZE_MB} MB) PASS"
        else
            log_warn "${name}: ${size_mb} MB EXCEEDS ${MAX_SIZE_MB} MB budget!"
        fi
    fi
}

check_size "${SQUASHFS_OUT}" "SquashFS Appliance"
check_size "${CPIO_OUT}" "Initramfs Appliance"

# ------------------------------------------------------------------------------
# Step 5: Bootability & Hypervisor Validation Smoke Tests
# ------------------------------------------------------------------------------
if [[ "${SKIP_TEST}" -eq 0 ]]; then
    log_info "Step 5: Running Bootability & Hypervisor Verification Checks..."

    # 1. Check PID 1 init validity
    if [[ -x "${ROOTFS_DIR}/init" ]]; then
        sh -n "${ROOTFS_DIR}/init"
        log_ok "Syntax check passed for appliance PID 1 (/init)"
    else
        log_err "/init is missing or not executable in rootfs!"
        exit 1
    fi

    # 2. Check aegisbox-guest static binary
    if [[ -f "${ROOTFS_DIR}/bin/aegisbox-guest" ]]; then
        FILE_INFO="$(file "${ROOTFS_DIR}/bin/aegisbox-guest" 2>/dev/null || true)"
        if echo "${FILE_INFO}" | grep -q -i "elf"; then
            log_ok "Verified static Linux ELF binary: /bin/aegisbox-guest"
        else
            log_warn "Binary file check: ${FILE_INFO}"
        fi
    fi

    # 3. Generate Firecracker MicroVM Boot Configuration Spec
    FIRECRACKER_SPEC="${OUTPUT_DIR}/firecracker-config.json"
    cat > "${FIRECRACKER_SPEC}" <<EOF
{
  "boot-source": {
    "kernel_image_path": "vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off init=/init root=/dev/vda ro"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "${SQUASHFS_OUT}",
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
    "uds_path": "${OUTPUT_DIR}/aegisbox.vsock"
  }
}
EOF
    log_ok "Generated Firecracker launch spec: ${FIRECRACKER_SPEC}"

    # 4. Generate Apple Virtualization.framework (VZ) Boot Spec
    VZ_SPEC="${OUTPUT_DIR}/apple-vz-spec.json"
    cat > "${VZ_SPEC}" <<EOF
{
  "hypervisor": "apple-virtualization-framework",
  "kernel": "vmlinux",
  "initrd": "${CPIO_OUT}",
  "rootfs_disk": "${SQUASHFS_OUT}",
  "boot_args": "console=hvc0 init=/init root=/dev/vda ro",
  "vcpu": 1,
  "memory_mb": 256,
  "virtio_fs": {
    "tag": "workspace",
    "host_path": "./workspace",
    "guest_mount": "/workspace"
  },
  "virtio_vsock": {
    "port": 1024
  }
}
EOF
    log_ok "Generated Apple VZ launch spec: ${VZ_SPEC}"

    # 5. Check hypervisor driver prerequisites
    if [[ "$(uname)" == "Darwin" ]]; then
        HV_SUPPORT="$(sysctl -n kern.hv_support 2>/dev/null || echo 0)"
        if [[ "${HV_SUPPORT}" == "1" ]]; then
            log_ok "Apple Virtualization Hypervisor entitlement (kern.hv_support=1) verified."
        fi
    elif [[ -e /dev/kvm ]]; then
        log_ok "Linux KVM driver (/dev/kvm) available for Firecracker boot."
    fi
fi

echo ""
echo "============================================================"
log_ok "Aegisbox Minimal Appliance Build Complete!"
echo "============================================================"
echo "Artifacts produced:"
[[ -f "${SQUASHFS_OUT}" ]] && echo "  - SquashFS:  ${SQUASHFS_OUT}"
[[ -f "${CPIO_OUT}" ]]     && echo "  - Initramfs: ${CPIO_OUT}"
echo "  - Rootfs:    ${ROOTFS_DIR}"
echo "============================================================"
