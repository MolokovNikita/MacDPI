package main

import (
	"fmt"
	"os"
	"strings"
)

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func installationScript(uid int) (string, error) {
	if uid < 501 {
		return "", fmt.Errorf("invalid UID")
	}
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(`set -eu
BASE='/Library/Application Support/MacDPI'
PLIST='/Library/LaunchDaemons/local.macdpi.helper.plist'
if [ -L "$BASE" ] || [ -L "$BASE/helper.log" ] || [ -L "$BASE/dns-backup.json" ] || [ -L "$BASE/diagnostics.jsonl" ]; then echo 'Refusing symlink installation directory' >&2; exit 1; fi
/usr/bin/install -d -o root -g wheel -m 755 "$BASE"
STAGED=$(/usr/bin/mktemp "$BASE/.helper.XXXXXX")
trap '/bin/rm -f "$STAGED"' EXIT
/usr/bin/install -o root -g wheel -m 755 %s "$STAGED"
/bin/launchctl bootout system/local.macdpi.helper 2>/dev/null || true
/bin/mv -f "$STAGED" "$BASE/macdpi-helper"
/bin/cat > "$PLIST" <<'MACDPI_PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>local.macdpi.helper</string>
<key>ProgramArguments</key><array><string>/Library/Application Support/MacDPI/macdpi-helper</string><string>--service</string><string>--uid</string><string>%d</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>3</integer>
<key>StandardOutPath</key><string>/Library/Application Support/MacDPI/helper.log</string>
<key>StandardErrorPath</key><string>/Library/Application Support/MacDPI/helper.log</string>
</dict></plist>
MACDPI_PLIST
/usr/sbin/chown root:wheel "$PLIST"
/bin/chmod 644 "$PLIST"
/bin/launchctl bootstrap system "$PLIST"
`, shellQuote(executable), uid), nil
}
