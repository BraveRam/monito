#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $EUID -ne 0 ]]; then
    echo 'This test needs root (CAP_BPF and CAP_NET_ADMIN). Build with make kernel-test-binaries first.' >&2
    exit 1
fi
export MONITO_EBPF_E2E=1
export MONITO_BIN_DIR="$PWD/bin"
# These tests use disposable databases/sockets and detach all BPF links on exit.
# They neither install a service nor modify the user's existing database.
./bin/bpf.test -test.run '^TestKernelConcurrentSnapshots$' -test.v -test.timeout 60s
./bin/e2e.test -test.run '^TestKernelEndToEnd$' -test.v -test.timeout 60s
