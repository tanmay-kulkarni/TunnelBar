#!/bin/bash
# Builds TunnelBar.app into ./build. Pass "install" to copy it to ~/Applications and (re)start it.
set -euo pipefail
cd "$(dirname "$0")"

APP=build/TunnelBar.app
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
swiftc -O -parse-as-library -target "$(uname -m)-apple-macos14" \
  Sources/TunnelBar.swift -o "$APP/Contents/MacOS/TunnelBar"
cp Info.plist "$APP/Contents/Info.plist"
codesign --force --sign - "$APP"
echo "Built $APP"

if [[ "${1:-}" == "install" ]]; then
  mkdir -p ~/Applications
  pkill -x TunnelBar 2>/dev/null && sleep 1 || true
  rm -rf ~/Applications/TunnelBar.app
  cp -R "$APP" ~/Applications/
  open ~/Applications/TunnelBar.app
  echo "Installed to ~/Applications/TunnelBar.app and started it"
fi
