# ais build and check targets.
#
#   make            # -> ./ais
#   make install    # -> ~/.local/bin/ais   (PREFIX=/usr/local for system-wide)
#   make release    # -> dist/ais_<version>_linux_{amd64,arm64}.tar.gz
#
# `make check` is what CI runs.

GO      ?= go
BINARY  := ais
CTL     := aisctl
PREFIX  ?= $(HOME)/.local
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS  = -s -w -X github.com/scuq/ais/internal/app.Version=$(VERSION) -X github.com/scuq/ais/internal/aisctl.Version=$(VERSION)

.PHONY: all build release install test test-integration vet fmt-check staticcheck shellcheck check clean

all: build

# CGO off: the ais binary is bind-mounted into distroless sidecars and must
# be static.
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/ais
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(CTL) ./cmd/aisctl

# Static Linux release archives for amd64 and arm64 in dist/, with SHA256SUMS.
#   make release VERSION=v0.2.0
RELEASE_ARCHES ?= amd64 arm64
release:
	rm -rf dist && mkdir -p dist
	@set -e; for arch in $(RELEASE_ARCHES); do \
		name=ais_$(VERSION)_linux_$$arch; dir=dist/$$name; mkdir -p $$dir; \
		echo "build $$name"; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $$dir/$(BINARY) ./cmd/ais; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $$dir/$(CTL) ./cmd/aisctl; \
		cp README.md CHANGELOG.md $$dir/; \
		tar -C dist -czf dist/$$name.tar.gz $$name; rm -rf $$dir; \
	done
	cd dist && sha256sum *.tar.gz > SHA256SUMS && cat SHA256SUMS

install: build
	install -d $(PREFIX)/bin
	install -m 0755 $(BINARY) $(PREFIX)/bin/$(BINARY)
	install -m 0755 $(CTL) $(PREFIX)/bin/$(CTL)
	@echo "installed $(PREFIX)/bin/$(BINARY) and $(PREFIX)/bin/$(CTL)"

test:
	$(GO) test ./...

# Needs a container engine and CLAUDE_CODE_OAUTH_TOKEN in the environment.
test-integration:
	$(GO) test -tags integration -count=1 ./...

vet:
	$(GO) vet ./...

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@latest ./...

shellcheck:
	shellcheck -S warning assets/entrypoint.sh

check: fmt-check vet test

clean:
	rm -f $(BINARY) $(CTL)
