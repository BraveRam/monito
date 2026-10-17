#!/usr/bin/env bash
# Exercise the extracted DEB's daemon, CLI, and TUI without installing it.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
deb_file="$(realpath "${1:?Usage: scripts/test-deb.sh path/to/monito.deb}")"
unpack="$(mktemp -d "${TMPDIR:-/tmp}/monito-deb-test.XXXXXX")"
trap 'rm -rf "$unpack"' EXIT
dpkg-deb --extract "$deb_file" "$unpack"
version="$(dpkg-deb --field "$deb_file" Version)"
test "$(dpkg-deb --field "$deb_file" Architecture)" = amd64
test "$("$unpack/usr/bin/monito" version)" = "monito version ${version%-*} (Linux/x86_64 eBPF)"
grep -q '^ExecStart=/usr/bin/monitod ' "$unpack/usr/lib/systemd/system/monito.service"
cd "$repo_root"
MONITO_BIN_DIR="$unpack/usr/bin" go test -count=1 -v ./integration
