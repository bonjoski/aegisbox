#!/bin/bash
# Exit on any error
set -e

if [ "$#" -ne 4 ]; then
    echo "Usage: ./package_macos.sh <path_to_icon.icns> <path_to_binary> <output_app_path> <version>"
    echo "Example: ./package_macos.sh desktop/src-tauri/icons/icon.icns desktop/src-tauri/target/debug/aegisbox-desktop bin/'Aegisbox Cockpit.app' 1.0.0"
    exit 1
fi

ICNS_SRC="$1"
BINARY_SRC="$2"
APP_DEST="$3"
VERSION="$4"
CONTENTS_DIR="${APP_DEST}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"

echo "Packaging ${APP_DEST}..."

rm -rf "${APP_DEST}"
mkdir -p "${MACOS_DIR}"
mkdir -p "${RESOURCES_DIR}"

# Copy icon
cp "${ICNS_SRC}" "${RESOURCES_DIR}/Aegisbox.icns"

# Copy binary
cp "${BINARY_SRC}" "${MACOS_DIR}/aegisbox-desktop"
chmod +x "${MACOS_DIR}/aegisbox-desktop"

# Info.plist
cat > "${CONTENTS_DIR}/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>aegisbox-desktop</string>
    <key>CFBundleIconFile</key>
    <string>Aegisbox</string>
    <key>CFBundleIdentifier</key>
    <string>com.bonjoski.aegisbox.desktop</string>
    <key>CFBundleName</key>
    <string>Aegisbox Cockpit</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>12.0</string>
    <key>LSUIElement</key>
    <false/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

echo "Successfully packaged ${APP_DEST}"
