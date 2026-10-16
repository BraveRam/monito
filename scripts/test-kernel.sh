#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ $EUID -ne 0 ]]; then
    echo 'This test needs root (CAP_BPF, CAP_NET_ADMIN, and CAP_PERFMON). Build with make kernel-test-binaries first.' >&2
    exit 1
fi
export MONITO_EBPF_E2E=1
export MONITO_BIN_DIR="$PWD/bin"
# These tests use disposable databases/sockets and detach all BPF links on exit.
# They neither install a service nor modify the user's existing database.
# Run the kernel tests with precisely the service's bounding set. Running only
# with unrestricted sudo can hide missing helper-specific capabilities.
capability_set=-all
while IFS= read -r line; do
    if [[ "$line" == CapabilityBoundingSet=* ]]; then
        for capability in ${line#*=}; do
            capability=${capability#CAP_}
            capability_set+=",+${capability,,}"
        done
    fi
done < dist/systemd/monito.service
if [[ "$capability_set" == -all ]]; then
    echo 'Service CapabilityBoundingSet is missing' >&2
    exit 1
fi
export MONITO_DAEMON_BOUNDING_SET="$capability_set"
setpriv --bounding-set="$capability_set" ./bin/bpf.test -test.run '^TestKernel' -test.v -test.timeout 60s
./bin/e2e.test -test.run '^TestKernel' -test.v -test.timeout 60s

./scripts/test-service.sh
