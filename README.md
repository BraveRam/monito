# Monito

A Linux network monitor that shows download, upload, live speed, and daily usage per application. The background collector keeps recording when you close the dashboard.

## Install

Requires Linux with cgroup v2 and eBPF support, Go 1.26.2+, and GCC. Developed and tested on Fedora.

The recommended setup installs a background systemd collector and the dashboard:

```bash
sudo dnf install go gcc make git
git clone https://github.com/BraveRam/monito.git
cd monito
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now monito
monito
```

Run `monito` as your regular user. Only installation and the collector service need root.

To update after pulling changes:

```bash
git pull
sudo make install
sudo systemctl daemon-reload
sudo systemctl restart monito
```

### Optional: binaries with Go

If you only need the binaries:

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

Usage includes IP headers and retransmissions. Loopback traffic counts at both sending and receiving apps. VPNs, proxies, and network offloads can make totals differ from interface counters or ISP bills.

History starts when collection starts and is stored at `/var/lib/monito/monito.db`. All local users can read system-wide usage through the collector.

## Test

```bash
make check                         # Vet and race tests
make e2e                           # Daemon, CLI, and TUI tests in preview mode
make kernel-test-binaries
sudo make install
sudo ./scripts/test-kernel.sh       # Live eBPF and service sandbox tests
```

## Uninstall

```bash
sudo make uninstall                # Keeps usage history
sudo make uninstall PURGE_DATA=1    # Also deletes history
```

## License

Dual-licensed under [MIT](LICENSE) or [GPL-2.0-only](LICENSE-GPL-2.0), at your choice. Bundled third-party files retain their own license notices.
