#!/bin/bash
# Build NetScan.app — a self-contained macOS app bundle.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
APP="$ROOT/build/NetScan.app"
NAME="NetScan"
BUNDLE_ID="com.local.netscan"
TARGET="${MACOS_TARGET:-13.0}"

echo "==> Building $NAME"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

ARCH="$(uname -m)"
swiftc \
  -O -whole-module-optimization \
  -target "${ARCH}-apple-macos${TARGET}" \
  -parse-as-library \
  -framework SwiftUI -framework AppKit \
  "$ROOT"/NetScanApp/Sources/*.swift \
  -o "$APP/Contents/MacOS/$NAME"

echo "==> Icon"
ICON_SRC="$ROOT/icon/AppIcon.icns"
if [ ! -f "$ICON_SRC" ]; then
  echo "    generating (no AppIcon.icns present)"
  ( cd "$ROOT/icon" \
    && swiftc -O -target "${ARCH}-apple-macos${TARGET}" GenerateIcon.swift -o generate-icon \
    && ./generate-icon . >/dev/null \
    && iconutil -c icns AppIcon.iconset -o AppIcon.icns )
fi
if [ -f "$ICON_SRC" ]; then
  cp "$ICON_SRC" "$APP/Contents/Resources/AppIcon.icns"
  echo "    using $ICON_SRC"
else
  echo "    warning: no icon produced, app will use the generic placeholder"
fi

echo "==> Bundling the scanning engine"
mkdir -p "$APP/Contents/Resources/engine"
cp -R "$ROOT/netscan" "$APP/Contents/Resources/engine/netscan"
find "$APP/Contents/Resources/engine" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$NAME</string>
  <key>CFBundleDisplayName</key><string>Network Scanner</string>
  <key>CFBundleExecutable</key><string>$NAME</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundleIdentifier</key><string>$BUNDLE_ID</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>$TARGET</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSPrincipalClass</key><string>NSApplication</string>
  <key>NSSupportsAutomaticTermination</key><true/>
  <key>NSLocalNetworkUsageDescription</key>
  <string>Network Scanner discovers devices, open ports and services on the networks this Mac is connected to.</string>
  <key>NSBonjourServices</key>
  <array>
    <string>_services._dns-sd._udp</string>
    <string>_device-info._tcp</string>
    <string>_http._tcp</string>
    <string>_airplay._tcp</string>
    <string>_smb._tcp</string>
    <string>_ipp._tcp</string>
  </array>
</dict>
</plist>
PLIST

# Ad-hoc signature: enough for macOS to remember Local Network permission.
codesign --force --deep --sign - "$APP" 2>/dev/null \
  && echo "==> Signed (ad-hoc)" \
  || echo "==> Warning: could not sign the bundle"

echo "==> Built $APP"
