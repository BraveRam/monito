# Monito: Linux Application Network Traffic Monitor

Monito is a reliable, lightweight Linux network traffic accounting system and Terminal User Interface (TUI) built in Go for Fedora Linux (systemd, cgroup v2). It attributes network usage directly to user applications and system services, maintaining persistent daily and hourly history in SQLite.

---

## Architecture

Monito cleanly separates the **privileged background collector daemon** (`monitod`) from the **unprivileged user interface and CLI** (`monito`):

```
┌────────────────────────────────────────────────────────────────────────┐
│                              Linux Kernel                              │
│                                                                        │
│   cgroup/sock_create             cgroup_skb/ingress & egress           │
│   (captures socket -> PID,       (root /sys/fs/cgroup: matches skb     │
│    cgroup, comm in socket storage)       storage to PID, classifies IPv4/IPv6) │
│               │                                   │                    │
│               └───────────────────┬───────────────┘                    │
│                                   ▼                                    │
│                       Cumulative Kernel Aggregation Map                           │
│                 {pid, category} -> {rx_bytes, tx_bytes}                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ BPF Snapshot Delta (1s)
┌───────────────────────────────────▼────────────────────────────────────┐
│                  Privileged Collector Daemon (monitod)                 │
│                                                                        │
│   • App Identity Resolver (/proc, cgroup v2, .desktop, Flatpak)        │
│   • Multi-process ancestry grouping (Chrome, Firefox, Electron)        │
│   • In-memory delta aggregation & 5s bounded flush to SQLite           │
│   • SQLite Engine (WAL mode, atomic migrations, rollups)               │
│   • Versioned HTTP-over-UDS server (/run/monito/monito.sock)           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Local Unix Domain Socket
┌───────────────────────────────────▼────────────────────────────────────┐
│                    Unprivileged Client (monito)                        │
│                                                                        │
│   • Interactive TUI (Bubble Tea, Bubbles, Lip Gloss)                   │
│   • Non-interactive CLI commands (today, apps, history, live, doctor)   │
│   • Machine-readable JSON reporting (--json)                           │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Continuous Accounting**: The background collector records traffic even when the TUI or terminal closes.
2. **Single Database Writer**: Only the collector writes to the SQLite database. Clients query a versioned local API over a Unix domain socket (`/run/monito/monito.sock`).
3. **Least Privilege**: The TUI and CLI never run as root. The system service runs as root with its capabilities bounded to `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON`. The read-only API socket permits all local users to query system-wide usage; it does not isolate usage by login account.

---

## Traffic Accounting Semantics

### eBPF Hook Selection & Socket Ownership
Attributing network traffic on Linux is complex due to asynchronous packet processing:
- **The Ingress Trap**: Ingress packet delivery executes inside software interrupt context (`softirqd`). At packet arrival, `bpf_get_current_pid_tgid()` returns `0` (swapper/idle) or an interrupted, completely unrelated task. Monito **never** assumes the current PID at a packet hook owns the packet.
- **Ownership Retention**:
  1. Monito hooks `cgroup/sock_create` in the creating application's process context.
  2. It stores `{ pid, cgroup_id, comm }` in socket-local eBPF storage and refreshes it in the syscall-context `TCP_LISTEN_CB`. `BPF_F_CLONE` copies that ownership from a listening socket to its accepted TCP children, without sampling a PID from handshake processing.
  3. Ingress and egress hooks read this retained ownership from the packet's socket. Accepted sockets are charged to the listener's creator; passing descriptors between processes does not transfer that ownership.
  4. Sockets open before startup are recovered when their application next calls TCP/UDP send or receive. Recovery uses function-entry hooks with the existing service capabilities. Bytes observed before ownership is recovered remain `Unattributed Traffic`; they are never reassigned retroactively. Kernel-only or otherwise unowned packets keep their observed traffic category.
  5. Userspace differences cumulative counters without deleting active entries. The flow map holds 16,384 PID/category entries with LRU eviction; generations detect recreated entries. Extreme churn exceeding that capacity between snapshots can still lose unsampled data. Allocation failures are exposed through `MapErrors`.


### What Bytes Mean
- **Measurement Layer**: Monito measures **IP-layer bytes** (`skb->len` at `cgroup_skb`).
- **Included**: IPv4/IPv6 headers (20–40 bytes), L4 TCP/UDP headers (8–32 bytes), and payload data.
- **Retransmissions**: Included in egress totals because retransmitted TCP segments consume real network interface bandwidth.
- **Excluded**: L2 Ethernet headers (14 bytes), VLAN tags, preamble, and frame check sequences.
- **Hardware Offloads (TSO / GSO / GRO)**: Aggregated super-packets correctly reflect the total IP payload size before segmentation or after reassembly.
- **Difference from Application Bytes**: Socket `read()` and `write()` calls measure raw payload bytes. Monito's IP-layer measurements are slightly higher due to headers and retransmissions.
- **Difference from ISP Billing**: ISP billing counters often include raw L2 framing, PPPoE/VLAN tags, carrier-grade NAT, and drop counters at the gateway.

### Traffic Categories
Monito classifies all traffic into four distinct categories:
1. **Loopback**: Traffic on interface index `1` (`lo`), `127.0.0.0/8`, or `::1`.
2. **Private / Local Network**: RFC 1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), unique local IPv6 (`fc00::/7`), Tailscale/CGNAT (`100.64.0.0/10`), and multicast (`224.0.0.0/4`, `ff00::/8`).
3. **External (Internet)**: All publicly routable internet addresses.
4. **Unknown / Unattributed**: Non-IP traffic or orphaned packets.

### VPNs, Tunnels, and Proxies
- When traffic routes through a local proxy (e.g. `127.0.0.1:8080`) or local VPN tunnel endpoint, destination-based inspection sees the local/tunnel IP.
- Monito inspects physical network interfaces (`/proc/net/dev`) as an independent reconciliation baseline.
- Monito **never** fabricates application attribution or forces app totals to match physical interface counters.

---

## Application Identity

Command-name and short-lived fallbacks are grouped with a full executable path only when that match is unique among recorded executables. When no path matches, the two legacy fallback formats for an identical command name share one command-name bucket; this does not establish an executable path. Distinct paths sharing a basename stay separate. Original traffic rows are retained; aliases combine the dashboard, live rates, and history without changing totals. New competing paths revoke an ambiguous alias automatically. Classification uses known executable names, desktop metadata, and service cgroups instead of process-name suffixes, and recognizes npm's `npm exec …` process titles as CLI tools.

PIDs are temporary identifiers recycled by the kernel. Monito builds persistent application identities:

1. **PID Reuse Defense**: Monito records the process start time from `/proc/<pid>/stat` (field 22) alongside the PID. If a PID is reused by a new process instance, the start time changes, automatically busting the cache.
2. **Multi-Process Ancestry Grouping**: Web browsers (Google Chrome, Firefox, Brave) and Electron applications (VS Code, Slack, Discord) spawn dozens of isolated renderers and utility processes. Monito inspects parent process ancestry (`PPid` from `/proc/<pid>/status`) to group all child processes into the parent application identity.
3. **Flatpak Applications**: Extracted from cgroup v2 scope paths (e.g. `app-flatpak-org.mozilla.firefox-*.scope`) or `.flatpak-info`.
4. **Systemd Services**: Identified via `/system.slice/<unit>.service` in `/proc/<pid>/cgroup` (e.g. `systemd:NetworkManager.service`, `systemd:systemd-resolved.service`).
5. **Desktop Applications**: Scans `/usr/share/applications`, `~/.local/share/applications`, and Flatpak export directories for `.desktop` metadata to provide clean display names.
6. **Short-Lived Processes**: Ephemeral tools (`curl`, `git`, `ssh`) often exit within milliseconds before `/proc` can be read. Monito stores the process command name (`comm`) and `cgroup_id` directly in an eBPF LRU map at socket creation, providing a command-name fallback after the process has terminated. Previously resolved process metadata is retained for late deltas.

---

## Persistence & Durability (SQLite)

- **Storage Location**:
  * System mode: `/var/lib/monito/monito.db`
  * User mode: `~/.local/share/monito/monito.db`
- **SQLite Configuration**: `PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;`.
- **Atomic Transactions**: Schema migrations and metric ingestions run in atomic transactions.
- **Checkpointing & Bounded Loss**: The collector normally flushes every 5 seconds. Failed writes retain pending records for retry and are logged. Graceful shutdown detaches accounting hooks, takes a final snapshot, and flushes pending records; persistent failures produce a nonzero exit. Power loss, map-capacity pressure, or extended storage failures can lose data; SQLite `synchronous=NORMAL` does not guarantee the latest commits survive power loss.
- **Timezone Handling**: Hourly buckets use UTC unix seconds. Daily rollups use the collector's local timezone and each record's observation time; history queries return the requested calendar window, including today.
- **History Retention**: Fine-grained hourly traffic buckets are pruned at startup and daily after 14 days, while daily rollups are preserved indefinitely.

---

## Installation & Security

### Minimum Capabilities
On Fedora 44 with Linux kernel 6.19 and `kernel.unprivileged_bpf_disabled = 2`, loading eBPF programs requires:
- `CAP_BPF`
- `CAP_NET_ADMIN`
- `CAP_PERFMON` (required by the kernel for the process-name helper)

The TUI and CLI run completely unprivileged. The background service runs as root with a bounded capability set and systemd filesystem hardening.

### Build from Source
```bash
# Install build dependencies (Fedora)
sudo dnf install -y clang llvm go make gcc kernel-headers python3

# Clone repository
git clone https://github.com/BraveRam/monito.git
cd monito

# Generate eBPF Go bindings from Linux UAPI headers and build binaries
make

# Or build using the committed eBPF bytecode (no Clang/bpf2go needed)
make build
```

### Install Systemd Service
```bash
# Install binaries and systemd unit
sudo make install

# Enable and start the background collector
sudo systemctl daemon-reload
sudo systemctl enable --now monito

# Verify collector status
monito doctor
monito status
```

### Uninstall
```bash
# Uninstall binaries and disable service (preserves database)
sudo make uninstall

# To completely purge database and configuration
sudo make uninstall PURGE_DATA=1
```

---

## CLI & TUI Usage

### Interactive TUI
Launch the interactive dashboard (no root required):
```bash
monito
```

#### TUI Keyboard Shortcuts
| Key | Action |
|-----|--------|
| `↑` / `↓` or `k` / `j` | Navigate application list |
| `Enter` | Open application details and 7-day history modal |
| `←` / `→` or `h` / `l` | Step backward / forward through calendar days |
| `T` | Reset view to Today |
| `/` | Activate live interactive search filter |
| `c` | Clear active search filter |
| `s` or `t` | Sort by Total Volume |
| `d` | Sort by Download (Inflow) |
| `u` | Sort by Upload (Outflow) |
| `r` | Sort by Current Transfer Rate |
| `n` | Sort alphabetically by Name |
| `?` | Toggle keyboard help modal |
| `q` or `Ctrl+C` | Quit |

For a separate user daemon, pass `--socket` to the CLI or set `MONITO_SOCKET` to its socket path. The default client path always matches the system service, `/run/monito/monito.sock`.

The dashboard distinguishes **Recorded** applications for the selected day from applications **Transferring** now. Traffic mix shows External, LAN/private, Loopback, and Unknown address classification. App attribution is a separate percentage: it measures how many recorded bytes have a known application owner. Historical unattributed bytes remain visible even after ownership recovery improves current traffic.

The system service uses `Type=notify`: `systemctl start` and `restart` wait until the API socket is listening and initialization is complete.

### Non-Interactive CLI Commands

#### Today's Usage Summary
```bash
monito today
monito today --json
```

#### Application Rankings
```bash
# Rank by total usage (default)
monito apps

# Sort by download or current rate
monito apps --sort=download
monito apps --sort=rate

# Filter by application name
monito apps --filter=firefox
monito apps --filter=curl --json
```

#### Historical Usage
```bash
monito history --app=flatpak:org.mozilla.firefox --days=7
monito history --app=exec:/usr/bin/curl --days=30 --json
```

#### Live Streaming Bandwidth Rates
```bash
monito live
monito live --json
```

#### Diagnostics & Health
```bash
monito status
monito doctor
```

---

## Verification & Test Results

Monito includes an automated test suite covering all critical subsystems:
```bash
make test
```

### Verification

`make check` runs `go vet` and all tests with the race detector. The integration suite launches the real daemon in explicit preview mode, exercises CLI/API queries, drives the TUI through a pseudo-terminal, and verifies history survives a restart. Preview mode never attaches kernel programs.

Live kernel verification is separate and requires root:

```bash
make kernel-test-binaries
sudo make install
sudo ./scripts/test-kernel.sh
```

The kernel tests first load and exercise the programs under the exact capability bounding set declared by the service, then verify concurrent packet accounting while snapshots run, then start the real daemon under the service capability bounding set, transfer data between distinct unprivileged TCP client/server processes (including connections open before startup), query the API as a regular user, and verify shutdown persistence and restart. They use temporary databases and sockets and do not install a service or overwrite existing history. The final check starts a disposable transient systemd unit with the real service sandbox and verifies its readiness notification and API; that unit is stopped automatically. This sandbox check requires the installed daemon to match the local build, so private home-directory permissions do not prevent execution.

The apps API emits traffic categories `0=loopback`, `1=private`, `2=external`, `3=unknown`, or `-1=mixed` when an app used several categories. This differs from the application-type label in `identity.category`.

---

## License

Dual MIT / GPLv2.
