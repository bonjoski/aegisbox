#!/usr/bin/env bash
#
# Aegisbox Installer Script
# Installs Aegisbox to /usr/local/bin and verifies the environment.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/bonjoski/aegisbox/main/scripts/install.sh | bash
#   or:
#   bash scripts/install.sh
#

set -euo pipefail

# Configuration
REPO="bonjoski/aegisbox"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
VERSION="${AEGISBOX_VERSION:-latest}"

# Terminal color helpers
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD="\033[1m"
  GREEN="\033[32m"
  BLUE="\033[34m"
  YELLOW="\033[33m"
  RED="\033[31m"
  RESET="\033[0m"
else
  BOLD=""
  GREEN=""
  BLUE=""
  YELLOW=""
  RED=""
  RESET=""
fi

log_info() {
  printf "${BLUE}${BOLD}==>${RESET} %s\n" "$1"
}

log_success() {
  printf "${GREEN}${BOLD}==>${RESET} %s\n" "$1"
}

log_warn() {
  printf "${YELLOW}${BOLD}Warning:${RESET} %s\n" "$1"
}

log_error() {
  printf "${RED}${BOLD}Error:${RESET} %s\n" "$1" >&2
}

# 1. Detect Operating System
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "${OS}" in
  darwin)
    PLATFORM="darwin"
    ;;
  linux)
    PLATFORM="linux"
    ;;
  msys*|mingw*|cygwin*)
    log_error "Windows shell detected. Please install Aegisbox via the Windows zip binary release or PowerShell."
    exit 1
    ;;
  *)
    log_error "Unsupported operating system: ${OS}"
    exit 1
    ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
  x86_64|amd64)
    TARGET_ARCH="amd64"
    ;;
  arm64|aarch64)
    TARGET_ARCH="arm64"
    ;;
  *)
    log_error "Unsupported architecture: ${ARCH}"
    exit 1
    ;;
esac

log_info "Detected target platform: ${PLATFORM}/${TARGET_ARCH}"

# 3. Create temporary workspace
TMP_DIR="$(mktemp -d -t aegisbox-install.XXXXXX)"
cleanup() {
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

# 4. Resolve and Download Release
INSTALLED_FROM_LOCAL=0

# Check for local build if available in current directory (e.g. development checkout)
if [ -f "./bin/aegisbox" ] && [ "${AEGISBOX_USE_LOCAL:-0}" = "1" ]; then
  log_info "Using local build binary from ./bin/aegisbox"
  cp ./bin/aegisbox "${TMP_DIR}/aegisbox"
  if [ -f "./bin/aegisbox-guest" ]; then
    cp ./bin/aegisbox-guest "${TMP_DIR}/aegisbox-guest"
  fi
  INSTALLED_FROM_LOCAL=1
fi

if [ "${INSTALLED_FROM_LOCAL}" -eq 0 ]; then
  log_info "Resolving release version for ${REPO}..."

  if [ "${VERSION}" = "latest" ]; then
    RELEASE_URL="https://api.github.com/repos/${REPO}/releases/latest"
    TAG="$(curl -fsSL -H "Accept: application/vnd.github.v3+json" "${RELEASE_URL}" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || true)"
    if [ -z "${TAG}" ]; then
      TAG="v0.1.0"
      log_warn "Could not resolve latest release via GitHub API, falling back to ${TAG}"
    fi
  else
    TAG="${VERSION}"
  fi

  # Strip leading 'v' for artifact names
  VERSION_NUM="${TAG#v}"

  # Try standard GoReleaser naming format
  ARCHIVE_NAME="aegisbox_${VERSION_NUM}_${PLATFORM}_${TARGET_ARCH}.tar.gz"
  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${TAG}/${ARCHIVE_NAME}"

  log_info "Downloading Aegisbox ${TAG} from ${DOWNLOAD_URL}..."
  HTTP_STATUS="$(curl -s -L -o "${TMP_DIR}/${ARCHIVE_NAME}" -w "%{http_code}" "${DOWNLOAD_URL}" || true)"

  if [ "${HTTP_STATUS}" != "200" ] || [ ! -s "${TMP_DIR}/${ARCHIVE_NAME}" ]; then
    # If GitHub release is not yet published or unreachable, check if local repo build exists
    if [ -f "./bin/aegisbox" ]; then
      log_warn "Remote release asset unavailable (${HTTP_STATUS}). Falling back to local ./bin/aegisbox binary."
      cp ./bin/aegisbox "${TMP_DIR}/aegisbox"
      if [ -f "./bin/aegisbox-guest" ]; then
        cp ./bin/aegisbox-guest "${TMP_DIR}/aegisbox-guest"
      fi
    else
      log_error "Failed to download release archive (${HTTP_STATUS})."
      log_error "URL: ${DOWNLOAD_URL}"
      log_error "Please ensure the release exists or build locally with 'go build -o bin/aegisbox ./cmd/aegisbox'."
      exit 1
    fi
  else
    log_info "Extracting ${ARCHIVE_NAME}..."
    tar -xzf "${TMP_DIR}/${ARCHIVE_NAME}" -C "${TMP_DIR}"
  fi
fi

# 5. Install to Target Directory
if [ ! -d "${INSTALL_DIR}" ]; then
  log_info "Creating directory ${INSTALL_DIR}..."
  if [ -w "$(dirname "${INSTALL_DIR}")" ]; then
    mkdir -p "${INSTALL_DIR}"
  else
    sudo mkdir -p "${INSTALL_DIR}"
  fi
fi

log_info "Installing binaries into ${INSTALL_DIR}..."

SUDO_CMD=""
if [ ! -w "${INSTALL_DIR}" ]; then
  if command -v sudo >/dev/null 2>&1; then
    log_info "Elevated permissions required to write to ${INSTALL_DIR}. Using sudo."
    SUDO_CMD="sudo"
  else
    log_error "Cannot write to ${INSTALL_DIR} and sudo is not available."
    exit 1
  fi
fi

${SUDO_CMD} cp "${TMP_DIR}/aegisbox" "${INSTALL_DIR}/aegisbox"
${SUDO_CMD} chmod 755 "${INSTALL_DIR}/aegisbox"

if [ -f "${TMP_DIR}/aegisbox-guest" ]; then
  ${SUDO_CMD} cp "${TMP_DIR}/aegisbox-guest" "${INSTALL_DIR}/aegisbox-guest"
  ${SUDO_CMD} chmod 755 "${INSTALL_DIR}/aegisbox-guest"
fi

log_success "Successfully installed Aegisbox to ${INSTALL_DIR}/aegisbox"

# 6. Run Aegisbox Diagnostics
log_info "Executing 'aegisbox doctor' environment diagnostics..."
echo ""
"${INSTALL_DIR}/aegisbox" doctor || log_warn "Diagnostics completed with warnings."

echo ""
log_success "Aegisbox installation and setup complete!"
log_info "Run 'aegisbox --help' to explore available commands."
