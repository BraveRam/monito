#!/usr/bin/env bash
# Exercise the actual service sandbox without changing the installed service.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $EUID -ne 0 ]]; then
    echo 'Run this service sandbox check with sudo.' >&2
    exit 1
fi
service_binary=/usr/local/bin/monitod
if ! cmp -s "$PWD/bin/monitod" "$service_binary"; then
    echo 'Install the current build with sudo make install before this check.' >&2
    exit 1
fi
unit="monito-check-$$"
properties=()
in_service=false
while IFS= read -r line; do
    [[ "$line" == '[Service]' ]] && { in_service=true; continue; }
    [[ "$line" == \[* ]] && { in_service=false; continue; }
    $in_service || continue
    case "$line" in
        Type=*|NotifyAccess=*|TimeoutStartSec=*|AmbientCapabilities=*|CapabilityBoundingSet=*|Protect*=*|PrivateTmp=*|MemoryDenyWriteExecute=*|LockPersonality=*|Restrict*=*|Limit*=*|ReadOnlyPaths=*|InaccessiblePaths=*)
            properties+=("--property=$line") ;;
    esac
done < dist/systemd/monito.service
cleanup() { systemctl stop "$unit.service" >/dev/null 2>&1 || true; }
trap cleanup EXIT
if ! systemd-run --collect --unit="$unit" "${properties[@]}" \
    --property="RuntimeDirectory=$unit" --property=RuntimeDirectoryMode=0755 \
    --property=Restart=no \
    "$service_binary" --db="/run/$unit/test.db" --socket="/run/$unit/test.sock"; then
    journalctl -u "$unit.service" -n 35 --no-pager >&2
    exit 1
fi
# Type=notify must make the API immediately usable when startup returns.
"$PWD/bin/monito" status --socket="/run/$unit/test.sock" --json
printf 'Full service sandbox and readiness check passed.\n'
