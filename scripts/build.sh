#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GO_BIN="${GO_BIN:-$ROOT/.tools/go/bin/go}"
if [ ! -x "$GO_BIN" ]; then GO_BIN="$(command -v go)"; fi
APP="$ROOT/build/MacDPI.app"
EXT="$APP/Contents/Library/SystemExtensions/local.macdpi.app.proxy.systemextension"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$EXT/Contents/MacOS"
(cd "$ROOT/daemon" && "$GO_BIN" build -trimpath -o "$APP/Contents/Resources/macdpi-daemon" .)
cp "$ROOT/macos/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
APP_SOURCES=(App.swift AppModel.swift ContentView.swift Glass.swift TabBar.swift)
swiftc -O -swift-version 5 -target "$(uname -m)-apple-macosx13.0" -parse-as-library \
  "${APP_SOURCES[@]/#/$ROOT/macos/}" -o "$APP/Contents/MacOS/MacDPI"
swiftc -O -swift-version 5 -target "$(uname -m)-apple-macosx13.0" -module-name MacDPIProxy "$ROOT/macos/ProxyProvider.swift" "$ROOT/macos/main.swift" -o "$EXT/Contents/MacOS/MacDPIProxy"
export MACDPI_BUILD_ROOT="$ROOT"
python3 "$ROOT/scripts/plists.py"
python3 "$ROOT/scripts/third_party.py" "$GO_BIN"
IDENTITY="${SIGNING_IDENTITY:--}"
codesign --force --options runtime --sign "$IDENTITY" --identifier local.macdpi.daemon "$APP/Contents/Resources/macdpi-daemon"
if [ "$IDENTITY" != "-" ]; then
  : "${APP_PROFILE:?Set APP_PROFILE to app provisioning profile}"
  : "${EXT_PROFILE:?Set EXT_PROFILE to extension provisioning profile}"
  cp "$APP_PROFILE" "$APP/Contents/embedded.provisionprofile"
  cp "$EXT_PROFILE" "$EXT/Contents/embedded.provisionprofile"
  python3 "$ROOT/scripts/signing_entitlements.py" "$APP_PROFILE" "$ROOT/macos/App.entitlements" "$ROOT/build/App.signing.entitlements"
  python3 "$ROOT/scripts/signing_entitlements.py" "$EXT_PROFILE" "$ROOT/macos/Extension.entitlements" "$ROOT/build/Extension.signing.entitlements"
  codesign --force --options runtime --sign "$IDENTITY" --entitlements "$ROOT/build/Extension.signing.entitlements" "$EXT"
  codesign --force --options runtime --sign "$IDENTITY" --entitlements "$ROOT/build/App.signing.entitlements" "$APP"
else
  rm -f "$APP/Contents/embedded.provisionprofile" "$EXT/Contents/embedded.provisionprofile"
  codesign --force --sign - "$EXT"
  codesign --force --sign - "$APP"
fi
codesign --verify --deep --strict "$APP"
echo "$APP"
