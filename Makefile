GO ?= go
CARGO ?= cargo
BPF_CARGO ?= cargo +nightly-2026-10-16
VERSION ?= 1.1.3
GO_LDFLAGS ?= -s -w
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSTEMD_DIR ?= /etc/systemd/system

.PHONY: all generate build test clean install uninstall

all: generate
	$(MAKE) build

# Regenerating bytecode needs Rust nightly + rust-src and bpf-linker on PATH.
# Normal builds/installations use the committed object and need only Go/GCC.
generate:
	RUSTFLAGS='--cfg bpf_target_arch="x86_64" -C link-arg=--btf' $(BPF_CARGO) build \
		--manifest-path bpf/rust/Cargo.toml --locked --release \
		--target bpfel-unknown-none -Z build-std=core
	cp bpf/rust/target/bpfel-unknown-none/release/monito-ebpf pkg/bpf/monito_x86_bpfel.o

build:
	@echo "Building Monito binaries..."
	mkdir -p bin
	$(GO) build -trimpath -ldflags="$(GO_LDFLAGS) -X main.version=$(VERSION)" -o bin/monito ./cmd/monito
	$(GO) build -trimpath -ldflags="$(GO_LDFLAGS) -X main.version=$(VERSION)" -o bin/monitod ./cmd/monitod
	$(GO) build -trimpath -ldflags="$(GO_LDFLAGS)" -o bin/prototype ./cmd/prototype
	@cp bin/monito monito
	@cp bin/monitod monitod
	@cp bin/prototype prototype

test:
	@echo "Running unit tests..."
	$(GO) test -v ./...

clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin monito monitod prototype *.sock *.pid *.db*

install: build
	@echo "Installing binaries to $(BINDIR)..."
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 bin/monito $(DESTDIR)$(BINDIR)/monito
	install -m 755 bin/monitod $(DESTDIR)$(BINDIR)/monitod
	@echo "Installing systemd unit to $(SYSTEMD_DIR)..."
	install -d $(DESTDIR)$(SYSTEMD_DIR)
	install -m 644 dist/systemd/monito.service $(DESTDIR)$(SYSTEMD_DIR)/monito.service
	@echo ""
	@echo "Installation complete!"
	@echo "To enable and start the collector daemon:"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now monito"
	@echo "To launch the interactive TUI (as regular user):"
	@echo "  monito"

uninstall:
	@echo "Stopping and disabling monito service..."
	-systemctl stop monito 2>/dev/null || true
	-systemctl disable monito 2>/dev/null || true
	@echo "Removing binaries and systemd unit..."
	rm -f $(DESTDIR)$(BINDIR)/monito $(DESTDIR)$(BINDIR)/monitod
	rm -f $(DESTDIR)$(SYSTEMD_DIR)/monito.service
	systemctl daemon-reload 2>/dev/null || true
	@if [ "$(PURGE_DATA)" = "1" ]; then \
		echo "Purging database and runtime state (/var/lib/monito, /run/monito)..."; \
		rm -rf /var/lib/monito /run/monito; \
	else \
		echo "Preserved historical database at /var/lib/monito. To purge: make uninstall PURGE_DATA=1"; \
	fi
	@echo "Uninstall complete."

.PHONY: check rust-test e2e kernel-test-binaries
rust-test:
	$(CARGO) fmt --manifest-path bpf/rust/Cargo.toml --check
	$(CARGO) test --manifest-path bpf/rust/Cargo.toml --locked --lib

check: rust-test
	$(GO) vet ./...
	$(GO) test -race ./...

e2e: build
	MONITO_BIN_DIR=$(CURDIR)/bin $(GO) test -count=1 -v ./integration

# Compile as the regular user. Only executing scripts/test-kernel.sh needs root.
kernel-test-binaries: build
	$(GO) test -c -o bin/bpf.test ./pkg/bpf
	$(GO) test -c -o bin/e2e.test ./integration

.PHONY: rpm
rpm:
	VERSION=$(VERSION) ./scripts/build-rpm.sh

.PHONY: deb
deb:
	VERSION=$(VERSION) ./scripts/build-deb.sh
