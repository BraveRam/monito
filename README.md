# Monito

A Linux network monitor with a Rust eBPF collector and a Go dashboard. It shows download, upload, live speed, and daily usage per application. The background collector keeps recording when you close the dashboard.

## Install

Packages include the dashboard, collector, and systemd service. Requires an x86_64/amd64 Linux system with cgroup v2, eBPF, and kernel BTF support.

**Fedora 44:**

```bash
sudo dnf install https://github.com/BraveRam/monito/releases/latest/download/monito.rpm
sudo systemctl enable --now monito
monito
```

**Ubuntu 24.04 LTS:**

Download the DEB first; apt installs the local file:

```bash
curl -fLO https://github.com/BraveRam/monito/releases/latest/download/monito.deb
sudo apt install ./monito.deb
sudo systemctl enable --now monito
monito
```

Run `monito` as your regular user. Only installation and the collector service need root.

To update, install the latest package again. For Ubuntu, download the new `.deb` first. If switching from a source installation, run `sudo make uninstall` in the old checkout first; this keeps your history.

To build from source (Go 1.26.2+ and GCC):

```bash
git clone https://github.com/BraveRam/monito.git
cd monito
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now monito
monito
```

To update after pulling changes:

```bash
git pull
sudo make install
sudo systemctl daemon-reload
sudo systemctl restart monito
```

### Optional: binaries with Go

If you only need the binaries and will start the collector yourself:

```bash
go install github.com/BraveRam/monito/cmd/monito@latest
go install github.com/BraveRam/monito/cmd/monitod@latest
```

Add `$(go env GOPATH)/bin` to your `PATH` (or use your configured `GOBIN`). This does not install or update the systemd service. For manual use, run `sudo "$(command -v monitod)"` in one terminal and `monito` as your regular user in another; collection stops when the daemon exits.

## Use

```bash
monito                             # Interactive dashboard
monito today                       # Today's usage
monito apps --sort=download         # Applications ranked by download
monito apps --filter=firefox        # Filter by name
monito live                        # Live transfer rates
monito history --app=exec:/usr/bin/curl --days=7
monito status                      # Collector status
monito doctor                      # Diagnose connection or setup issues
```

Add `--json` to reporting commands for machine-readable output.

Dashboard keys: `↑/↓` select, `Enter` details, `←/→` change day, `T` today, `/` filter, `c` clear filter, `t/d/u/r/n` sort by total/download/upload/rate/name, `?` help, `q` quit.

## Reading the dashboard

- **Recorded:** identified apps with usage on the selected day.
- **Transferring:** identified apps moving traffic now.
- **Traffic mix:** external, LAN/private, loopback, or unknown network traffic.
- **App attribution:** percentage of bytes with a known app owner. Unattributed bytes cannot be assigned retroactively.

Sizes and rates use decimal units: 1 KB = 1,000 bytes and 1 GB = 1,000,000,000 bytes.

Usage includes IP headers and retransmissions. Loopback traffic counts at both sending and receiving apps. VPNs, proxies, and network offloads can make totals differ from interface counters or ISP bills.

History starts when collection starts and is stored at `/var/lib/monito/monito.db`. All local users can read system-wide usage through the collector.

## Test

```bash
make check                         # Rust tests, Go vet, and race tests
make e2e                           # Daemon, CLI, and TUI tests in preview mode
make kernel-test-binaries
sudo make install
sudo ./scripts/test-kernel.sh       # Live eBPF and service sandbox tests
```

The Rust collector build and developer requirements are documented in [bpf/rust](bpf/rust/README.md). Normal builds and `go install` use the included bytecode and do not need Rust.

Build RPMs with `make rpm` (`rpm-build`, `systemd-rpm-macros`) or DEBs on Ubuntu with `make deb` (`build-essential`, `debhelper`, `dpkg-dev`, `golang-any`, `python3`). Outputs go to `dist/rpm/` and `dist/deb/`. Test extracted binaries with `scripts/test-rpm.sh path/to/package.rpm` or `scripts/test-deb.sh path/to/package.deb`.

Version tags matching the RPM spec and Debian changelog run CI and publish both packages on GitHub Releases.

## Uninstall

Fedora: `sudo dnf remove monito`. Ubuntu: `sudo apt remove monito`. Both keep usage history.

For a source installation:

```bash
sudo make uninstall                # Keeps usage history
sudo make uninstall PURGE_DATA=1    # Also deletes history
```

## License

Dual-licensed under [MIT](LICENSE) or [GPL-2.0-only](LICENSE-GPL-2.0), at your choice. Bundled third-party files retain their own license notices.
