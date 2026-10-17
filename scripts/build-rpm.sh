#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${VERSION:-1.0.0}"
spec_version="$(rpmspec -q --srpm --qf '%{VERSION}' "$repo_root/packaging/rpm/monito.spec")"
if [[ "$version" != "$spec_version" ]]; then
    printf 'Version %s does not match RPM spec version %s\n' "$version" "$spec_version" >&2
    exit 1
fi
topdir="$(mktemp -d "${TMPDIR:-/tmp}/monito-rpmbuild.XXXXXX")"
trap 'rm -rf "$topdir"' EXIT

mkdir -p "$topdir"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$topdir/tmp"
export GOTMPDIR="$topdir/tmp"
tar -czf "$topdir/SOURCES/monito-${version}.tar.gz" \
    --transform="flags=r;s|^|monito-${version}/|" \
    --exclude='./.git' \
    --exclude='./bin' \
    --exclude='./dist/rpm' \
    --exclude='./bpf/rust/target' \
    --exclude='./monito' \
    --exclude='./monitod' \
    --exclude='./prototype' \
    --exclude='*.db*' \
    --exclude='*.sock' \
    -C "$repo_root" .

rpmbuild -bb \
    --define "_topdir $topdir" \
    --define "_tmppath $topdir/tmp" \
    "$repo_root/packaging/rpm/monito.spec"

mkdir -p "$repo_root/dist/rpm"
cp "$topdir"/RPMS/x86_64/monito-*.rpm "$repo_root/dist/rpm/"
printf 'RPM created: %s\n' "$repo_root"/dist/rpm/monito-*.rpm
