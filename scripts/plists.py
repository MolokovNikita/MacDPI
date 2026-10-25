"""Writes Info.plist files for the app bundle and its network extension."""

import os
import pathlib
import plistlib

root = pathlib.Path(os.environ["MACDPI_BUILD_ROOT"])
app = root / "build/MacDPI.app/Contents"
extension = app / "Library/SystemExtensions/local.macdpi.app.proxy.systemextension/Contents"
signed = os.environ.get("SIGNING_IDENTITY", "-") != "-"

common = {
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleVersion": "12",
    "CFBundleShortVersionString": "0.5.0",
    "LSMinimumSystemVersion": "13.0",
}

app_info = common | {
    "CFBundleIdentifier": "local.macdpi.app",
    "CFBundleExecutable": "MacDPI",
    "CFBundleName": "MacDPI",
    "CFBundlePackageType": "APPL",
    "CFBundleIconFile": "AppIcon",
    "NSPrincipalClass": "NSApplication",
    "NSHumanReadableCopyright": "MacDPI contributors",
    "MacDPIHasSignedExtension": signed,
    "NSSystemExtensionUsageDescription": "MacDPI processes HTTPS connections locally to apply the selected DPI bypass strategy.",
}

extension_info = common | {
    "CFBundleIdentifier": "local.macdpi.app.proxy",
    "CFBundleExecutable": "MacDPIProxy",
    "CFBundleName": "MacDPI Network Extension",
    "CFBundlePackageType": "SYSX",
    "NetworkExtension": {
        "NEProviderClasses": {
            "com.apple.networkextension.app-proxy": "MacDPIProxy.ProxyProvider",
        },
    },
}

for directory, info in [(app, app_info), (extension, extension_info)]:
    (directory / "Info.plist").write_bytes(plistlib.dumps(info))
