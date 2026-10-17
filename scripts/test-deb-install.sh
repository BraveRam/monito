#!/usr/bin/env bash
# Destructive lifecycle checks are restricted to a fresh disposable container.
set -euo pipefail
if [[ $EUID -ne 0 ]] || [[ ! -f /.dockerenv && ! -f /run/.containerenv ]]; then
    echo 'Run only as root in a disposable Ubuntu container.' >&2
    exit 1
fi
if [[ -e /var/lib/monito ]] || dpkg-query -W monito >/dev/null 2>&1; then
    echo 'Lifecycle checks require a container without an existing Monito installation.' >&2
    exit 1
fi
deb_file="$(realpath "${1:?Usage: scripts/test-deb-install.sh path/to/monito.deb}")"
version="$(dpkg-deb --field "$deb_file" Version)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Exercise a real dpkg version upgrade, using the same payload as the old fixture.
dpkg-deb --raw-extract "$deb_file" "$work/previous"
sed -i "s/^Version:.*/Version: ${version%-*}~ci-1/" "$work/previous/DEBIAN/control"
dpkg-deb --build --root-owner-group "$work/previous" "$work/previous.deb"
apt-get install -y "$work/previous.deb"
test ! -L /etc/systemd/system/multi-user.target.wants/monito.service
systemctl enable monito
mkdir -p /var/lib/monito
printf 'preserve usage history\n' > /var/lib/monito/monito.db

apt-get install -y "$deb_file"
test "$(dpkg-query -W -f='${Version}' monito)" = "$version"
test "$(monito version)" = "monito version ${version%-*} (Linux/x86_64 eBPF)"
dpkg --verify monito
test -L /etc/systemd/system/multi-user.target.wants/monito.service
systemd-analyze verify /usr/lib/systemd/system/monito.service
test ! -e /usr/share/applications/monito.desktop
grep -q 'preserve usage history' /var/lib/monito/monito.db

dpkg --remove monito
test ! -e /usr/bin/monito
test ! -e /usr/bin/monitod
test ! -e /usr/lib/systemd/system/monito.service
grep -q 'preserve usage history' /var/lib/monito/monito.db
dpkg --purge monito
test ! -L /etc/systemd/system/multi-user.target.wants/monito.service
grep -q 'preserve usage history' /var/lib/monito/monito.db
printf 'Ubuntu install, upgrade, removal, and history preservation checks passed.\n'
