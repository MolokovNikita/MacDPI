#!/bin/bash
set -euo pipefail
if [ "$(id -u)" != 0 ]; then echo 'Run with sudo to remove the installed system helper.' >&2; exit 1; fi
BASE='/Library/Application Support/MacDPI'
PLIST='/Library/LaunchDaemons/local.macdpi.helper.plist'
# Ask the installed service to restore network settings before removing it.
if [ -f "$PLIST" ] && [ -x "$BASE/macdpi-helper" ]; then
  MACDPI_OWNER_UID=$(/usr/libexec/PlistBuddy -c 'Print :ProgramArguments:3' "$PLIST")
  "$BASE/macdpi-helper" --control stop --uid "$MACDPI_OWNER_UID"
  /bin/launchctl bootout system/local.macdpi.helper
fi
if [ -f "$BASE/dns-backup.json" ]; then echo 'DNS recovery is incomplete; helper files preserved.' >&2; exit 1; fi
/bin/rm -f "$PLIST" "$BASE/macdpi-helper" "$BASE/helper.log"
echo 'MacDPI system helper removed. The project and application are preserved.'
