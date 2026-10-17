#!/usr/bin/env bash
# Boot a real GA kernel without root/KVM. Build kernel-test-binaries first.
set -euo pipefail
cd "$(dirname "$0")/.."
kernel=$(realpath "${1:?usage: test-kernel-vm.sh vmlinuz busybox-static}")
busybox=$(realpath "${2:?provide an extracted static busybox binary}")
work=$(mktemp -d /tmp/monito-kernel-vm.XXXXXX)
trap 'rm -rf "$work"' EXIT
root="$work/root"
package_bin="${MONITO_BIN_DIR:-$PWD/bin}"
mkdir -p "$root"/{bin,proc,sys,dev,tmp}
chmod 1777 "$root/tmp"
cp "$busybox" "$root/bin/busybox"
cp "$package_bin/monito" "$package_bin/monitod" bin/{bpf.test,e2e.test} "$root/bin/"
# Preserve loader/library paths for dynamically linked Go/SQLite binaries.
for binary in "$package_bin/monito" "$package_bin/monitod" bin/{bpf.test,e2e.test}; do
    while read -r library; do
        mkdir -p "$root$(dirname "$library")"
        cp -L "$library" "$root$library"
    done < <(ldd "$binary" | awk '/=> \/|^[[:space:]]*\// {for(i=1;i<=NF;i++) if($i ~ /^\//) print $i}')
done
cat > "$root/init" <<'INIT'
#!/bin/busybox sh
/bin/busybox --install -s /bin
export PATH=/bin HOME=/tmp TMPDIR=/tmp
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /sys/fs/cgroup
mount -t cgroup2 cgroup2 /sys/fs/cgroup
ip link set lo up
uname -r
export MONITO_EBPF_E2E=1 MONITO_BIN_DIR=/bin MONITO_E2E_START_TIMEOUT=60s
if /bin/bpf.test -test.run '^TestKernel' -test.v -test.timeout 90s &&
   /bin/e2e.test -test.run '^TestKernel' -test.v -test.timeout 180s; then
    echo MONITO_KERNEL_VM_PASS
else
    echo MONITO_KERNEL_VM_FAIL
fi
poweroff -f
INIT
chmod 755 "$root/init"
(cd "$root" && find . -print0 | cpio --null -o --format=newc --quiet) | gzip > "$work/initramfs.gz"
timeout 240 qemu-system-x86_64 -accel tcg -cpu max -smp 2 -m 1024 \
    -kernel "$kernel" -initrd "$work/initramfs.gz" \
    -append 'console=ttyS0 rdinit=/init panic=-1 quiet' \
    -nographic -no-reboot -nic none 2>&1 | tee "$work/output.log"
grep -q '^MONITO_KERNEL_VM_PASS' "$work/output.log"
