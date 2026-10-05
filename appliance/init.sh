#!/bin/sh
# ==============================================================================
# Aegisbox MicroVM Appliance Init Script (PID 1)
# ==============================================================================
# This script serves as the minimal PID 1 process for the Aegisbox MicroVM.
# Responsibilities:
# 1. Mount virtual kernel filesystems (/proc, /sys, /dev, /dev/pts, /dev/shm).
# 2. Mount host workspace shared via virtiofs or 9p at /workspace.
# 3. Configure loopback and vsock networking.
# 4. Supervise /bin/aegisbox-guest daemon listening on port 1024.
# ==============================================================================

set -u

# Ensure safe default umask
umask 022

echo "============================================================"
echo "🛡️  Aegisbox MicroVM Appliance Initializing (PID 1)"
echo "============================================================"

# ------------------------------------------------------------------------------
# 1. Create Core Filesystem Hierarchy
# ------------------------------------------------------------------------------
mkdir -p /proc /sys /dev /dev/pts /dev/shm /workspace /root /tmp /run /var/run /var/log

# Mount virtual filesystems
mount -t proc proc /proc -o nosuid,noexec,nodev 2>/dev/null || true
mount -t sysfs sysfs /sys -o nosuid,noexec,nodev 2>/dev/null || true

# Devtmpfs or tmpfs for /dev
if ! mountpoint -q /dev 2>/dev/null; then
    mount -t devtmpfs devtmpfs /dev -o mode=0755,nosuid 2>/dev/null || \
    mount -t tmpfs tmpfs /dev -o mode=0755,nosuid 2>/dev/null || true
fi

# Ensure essential device nodes exist (vital for minimal initramfs/cpio)
[ -e /dev/null ]    || mknod -m 666 /dev/null c 1 3 2>/dev/null || true
[ -e /dev/zero ]    || mknod -m 666 /dev/zero c 1 5 2>/dev/null || true
[ -e /dev/full ]    || mknod -m 666 /dev/full c 1 7 2>/dev/null || true
[ -e /dev/random ]  || mknod -m 666 /dev/random c 1 8 2>/dev/null || true
[ -e /dev/urandom ] || mknod -m 666 /dev/urandom c 1 9 2>/dev/null || true
[ -e /dev/tty ]     || mknod -m 666 /dev/tty c 5 0 2>/dev/null || true
[ -e /dev/console ] || mknod -m 600 /dev/console c 5 1 2>/dev/null || true
[ -e /dev/ptmx ]    || mknod -m 666 /dev/ptmx c 5 2 2>/dev/null || true

# Mount devpts, shm, tmp, run
mount -t devpts devpts /dev/pts -o gid=5,mode=620,noexec,nosuid 2>/dev/null || \
mount -t devpts devpts /dev/pts 2>/dev/null || true

mount -t tmpfs tmpfs /dev/shm -o mode=1777,nosuid,nodev 2>/dev/null || true
mount -t tmpfs tmpfs /tmp -o mode=1777,nosuid,nodev 2>/dev/null || true
mount -t tmpfs tmpfs /run -o mode=0755,nosuid,nodev 2>/dev/null || true

# Run mdev if available to populate any dynamic devices
if command -v mdev >/dev/null 2>&1; then
    mdev -s 2>/dev/null || true
fi

echo "[init] Pseudo-filesystems mounted: /proc, /sys, /dev, /dev/pts, /dev/shm"

# ------------------------------------------------------------------------------
# 2. Mount Host Workspace (/workspace) via VirtioFS or 9p
# ------------------------------------------------------------------------------
WORKSPACE_MOUNTED=0

# Try VirtioFS first (preferred high-performance interface for microVMs)
for tag in workspace aegisbox_workspace hostshare host; do
    if mount -t virtiofs "$tag" /workspace 2>/dev/null; then
        echo "[init] ✅ Host workspace mounted via virtiofs (tag: '${tag}') at /workspace"
        WORKSPACE_MOUNTED=1
        break
    fi
done

# If VirtioFS failed, try 9p (virtio-9p standard across QEMU/Apple VZ)
if [ "$WORKSPACE_MOUNTED" -eq 0 ]; then
    for tag in workspace aegisbox_workspace hostshare host; do
        if mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576,rw "$tag" /workspace 2>/dev/null; then
            echo "[init] ✅ Host workspace mounted via 9p (tag: '${tag}') at /workspace"
            WORKSPACE_MOUNTED=1
            break
        fi
    done
fi

if [ "$WORKSPACE_MOUNTED" -eq 0 ]; then
    echo "[init] ℹ️ Host workspace not attached via virtiofs/9p. Using isolated local /workspace"
    mkdir -p /workspace
fi

# ------------------------------------------------------------------------------
# 3. Configure Networking (Loopback & VSOCK)
# ------------------------------------------------------------------------------
# Setup loopback
if ip link set lo up 2>/dev/null; then
    ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true
elif ifconfig lo 127.0.0.1 up 2>/dev/null; then
    true
fi
echo "[init] ✅ Loopback networking configured (127.0.0.1)"

# Ensure /dev/vsock device nodes exist
if [ ! -e /dev/vsock ]; then
    mknod /dev/vsock c 10 241 2>/dev/null || true
fi
if [ ! -e /dev/vhost-vsock ]; then
    mknod /dev/vhost-vsock c 10 241 2>/dev/null || true
fi

# Load virtio vsock kernel module if modular
modprobe vmw_vsock_virtio_transport 2>/dev/null || true
modprobe vhost_vsock 2>/dev/null || true

# Bring up any detected Ethernet interfaces (e.g. eth0 in bridged/TAP mode)
if ip link set eth0 up 2>/dev/null; then
    echo "[init] Interface eth0 brought up"
    # Optional DHCP client trigger in background if available
    if command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i eth0 -b -s /etc/udhcpc/default.script -p /var/run/udhcpc.eth0.pid 2>/dev/null || true
    fi
fi

# ------------------------------------------------------------------------------
# 4. Environment & Daemon Supervision
# ------------------------------------------------------------------------------
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HOME="/root"
export USER="root"
export TERM="linux"
hostname aegisbox-microvm 2>/dev/null || true

# Locate guest binary
GUEST_BIN="/bin/aegisbox-guest"
if [ ! -x "$GUEST_BIN" ]; then
    if [ -x "/usr/local/bin/aegisbox-guest" ]; then
        GUEST_BIN="/usr/local/bin/aegisbox-guest"
    elif command -v aegisbox-guest >/dev/null 2>&1; then
        GUEST_BIN="$(command -v aegisbox-guest)"
    else
        echo "[init] ⚠️ /bin/aegisbox-guest not found! Dropping to rescue shell."
        exec /bin/sh
    fi
fi

echo "[init] 🚀 Launching ${GUEST_BIN} -port 1024..."
"$GUEST_BIN" -port 1024 &
GUEST_PID=$!
echo "[init] Aegisbox guest daemon started (PID: ${GUEST_PID})"

# Clean shutdown handler
shutdown() {
    echo "[init] Shutdown signal received. Terminating guest daemon..."
    kill -TERM "$GUEST_PID" 2>/dev/null || true
    wait "$GUEST_PID" 2>/dev/null || true
    sync
    echo "[init] Powering off system..."
    poweroff -f 2>/dev/null || reboot -f 2>/dev/null || exit 0
}

trap shutdown INT TERM

# PID 1 supervisor loop: keeps appliance running, reaps zombie processes
while true; do
    if ! kill -0 "$GUEST_PID" 2>/dev/null; then
        echo "[init] ⚠️ aegisbox-guest exited. Restarting daemon in 1s..."
        sleep 1
        "$GUEST_BIN" -port 1024 &
        GUEST_PID=$!
        echo "[init] aegisbox-guest restarted (PID: ${GUEST_PID})"
    fi
    # Wait for any child process to terminate (reaping zombies)
    wait -n "$GUEST_PID" 2>/dev/null || sleep 2
done
