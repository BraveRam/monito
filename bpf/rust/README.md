# Rust eBPF collector

This crate replaces the C collector. The Go daemon loads its compiled ELF object; the API, database, and dashboard stay in Go.

## Build

Regenerating bytecode requires Rust nightly with `rust-src` and `bpf-linker` on your `PATH`:

```bash
rustup toolchain install nightly-2026-10-16 --component rust-src,rustfmt
cargo install bpf-linker --version 0.12.0 --locked
make generate
make build
```

Run these from the repository root. `BPF_CARGO` can select another nightly toolchain. The default is pinned to `nightly-2026-10-16`, verified with `bpf-linker` 0.12.0. Cargo dependencies are locked. Rust nightly is needed for building `core` for BPF and emitting atomic XADD updates.

`make build`, `make install`, and `go install` use the committed `pkg/bpf/monito_x86_bpfel.o` and do not require Rust. The object currently targets little-endian BPF with x86-64 kernel context bindings.

## Verify

```bash
make check
make e2e
make kernel-test-binaries
sudo make install
sudo ./scripts/test-kernel.sh
```

Host Rust tests cover address classification and shared structure layouts. Go tests check the embedded object's map layouts, socket cloning flags, hook metadata, and atomic accounting. They also reject unexpected BPF subprogram calls: small structure initialization and copies use explicit volatile stores to prevent LLVM from emitting verifier-incompatible global `memset`/`memmove` calls. Kernel tests verify loading, socket ownership, TCP/UDP recovery, concurrent snapshots, end-to-end usage, persistence, and the systemd sandbox. Host tests cannot establish kernel verifier acceptance.

## Compatibility

Keep map names, field order, sizes, program symbols, traffic categories, and counter indices compatible with `pkg/bpf/monito_x86_bpfel.go`. All shared values use `#[repr(C)]`. Packet hooks look up socket ownership; they never infer ownership from the currently executing task. Listener ownership is cloned to accepted sockets; pre-existing TCP/UDP sockets are recovered at application I/O.

`SocketStorage` uses an explicit BTF map definition because Aya's storage wrapper does not currently expose `BPF_F_CLONE`. The other maps and program entry points use Aya. The counter increment uses Rust's atomic intrinsic because the BPF target does not expose `AtomicU64::fetch_add`; the generated instruction must remain atomic under concurrent packet processing.
