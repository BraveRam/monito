#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
deb_version="$(dpkg-parsechangelog -l "$repo_root/packaging/deb/debian/changelog" -SVersion)"
version="${VERSION:-${deb_version%-*}}"
if [[ "$version" != "${deb_version%-*}" ]]; then
    printf 'Version %s does not match Debian changelog version %s\n' "$version" "$deb_version" >&2
    exit 1
fi
if [[ "$(dpkg --print-architecture)" != amd64 || "$(go env GOOS)/$(go env GOARCH)" != linux/amd64 ]]; then
    echo 'DEB builds currently require Linux amd64.' >&2
    exit 1
fi
work="$(mktemp -d "${TMPDIR:-/tmp}/monito-deb-build.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/source"
tar -c --exclude='./.git' --exclude='./bin' --exclude='./dist/rpm' \
    --exclude='./dist/deb' --exclude='./bpf/rust/target' \
    --exclude='./monito' --exclude='./monitod' --exclude='./prototype' \
    --exclude='*.db*' --exclude='*.sock' -C "$repo_root" . | tar -x -C "$work/source"
cp -a "$work/source/packaging/deb/debian" "$work/source/debian"
(cd "$work/source" && dpkg-buildpackage --build=binary --no-sign)
mkdir -p "$repo_root/dist/deb"
cp "$work"/monito_"$deb_version"_amd64.deb "$repo_root/dist/deb/"
printf 'DEB created: %s\n' "$repo_root/dist/deb/monito_${deb_version}_amd64.deb"
