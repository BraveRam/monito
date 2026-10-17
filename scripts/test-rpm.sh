#!/usr/bin/env bash
# Verify the shipped payload and exercise its daemon, CLI, and TUI without root.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rpm_file="$(realpath "${1:?Usage: scripts/test-rpm.sh path/to/monito.rpm}")"
unpack="$(mktemp -d "${TMPDIR:-/tmp}/monito-rpm-test.XXXXXX")"
trap 'rm -rf "$unpack"' EXIT

rpm --checksig "$rpm_file"
rpm2cpio "$rpm_file" | (cd "$unpack" && cpio -idm --quiet)
version="$(rpm -qp --qf '%{VERSION}' "$rpm_file")"
test "$("$unpack/usr/bin/monito" version)" = "monito version $version (Linux/x86_64 eBPF)"
grep -q '^ExecStart=/usr/bin/monitod ' "$unpack/usr/lib/systemd/system/monito.service"
cd "$repo_root"
MONITO_BIN_DIR="$unpack/usr/bin" go test -count=1 -v ./integration
