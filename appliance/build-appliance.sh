#!/usr/bin/env bash
set -euo pipefail

echo "🔨 Building Aegisbox Minimal Appliance Rootfs..."
ROOTFS_DIR="build/rootfs"
mkdir -p "${ROOTFS_DIR}"

# Build guest daemon
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o "${ROOTFS_DIR}/aegisbox-guest" ./cmd/aegisbox-guest

echo "✅ Guest daemon built at ${ROOTFS_DIR}/aegisbox-guest"
echo "📦 Ready to package into rootfs.squashfs"
