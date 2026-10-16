CC ?= clang
GO ?= go
BPF2GO ?= $(GO) run github.com/cilium/ebpf/cmd/bpf2go
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
SYSTEMD_DIR ?= /etc/systemd/system

.PHONY: all generate build test clean install uninstall

all: generate
	$(MAKE) build

generate:
	@echo "Generating eBPF bytecode and Go bindings..."
	$(BPF2GO) -cc clang -go-package bpf -output-dir pkg/bpf -target amd64 \
		-type flow_key -type flow_metrics -type proc_info \
		Monito bpf/monito.c -- -I./bpf

build:
	@echo "Building Monito binaries..."
	mkdir -p bin
	$(GO) build -trimpath -ldflags="-s -w" -o bin/monito ./cmd/monito
	$(GO) build -trimpath -ldflags="-s -w" -o bin/monitod ./cmd/monitod
	$(GO) build -trimpath -ldflags="-s -w" -o bin/prototype ./cmd/prototype
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

.PHONY: check e2e kernel-test-binaries
check:
	$(GO) vet ./...
	$(GO) test -race ./...

e2e: build
	MONITO_BIN_DIR=$(CURDIR)/bin $(GO) test -count=1 -v ./integration

# Compile as the regular user. Only executing scripts/test-kernel.sh needs root.
kernel-test-binaries: build
	$(GO) test -c -o bin/bpf.test ./pkg/bpf
	$(GO) test -c -o bin/e2e.test ./integration
