BIN        := knell
PKG        := github.com/0xCyrildev/knell
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     := $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
DATE       := $(shell git log -1 --format=%cI HEAD 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w -X $(PKG)/internal/build.Version=$(VERSION) -X $(PKG)/internal/build.Commit=$(COMMIT) -X $(PKG)/internal/build.Date=$(DATE)
GO         ?= go
PREFIX     ?= /usr/local
DIST       := dist

.PHONY: all build install uninstall test race cover vet fmt lint tidy clean release docker check

all: fmt vet build test

build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BIN) ./cmd/$(BIN)

install:
	$(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/$(BIN)

uninstall:
	rm -f $(PREFIX)/bin/$(BIN)

# -race matters here: the collector sweeps on a ticker, writes SQLite and spawns
# one goroutine per notify hook.
test:
	$(GO) test -count=1 ./...

race:
	$(GO) test -race -count=1 ./...

cover:
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

# Fails if anything is unformatted, for CI.
fmtcheck:
	@out=$$(gofmt -l ./cmd ./internal); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	@golangci-lint run ./... 2>/dev/null || echo "golangci-lint not installed; vet is the minimum bar"

tidy:
	$(GO) mod tidy

# Static binaries: modernc.org/sqlite is pure Go, so CGO is not needed and the
# result runs on a host with no libc toolchain.
release: clean
	@mkdir -p $(DIST)
	@for goos in linux darwin windows; do \
		for goarch in amd64 arm64; do \
			ext=""; [ $$goos = windows ] && ext=".exe"; \
			echo "  build $$goos/$$goarch"; \
			CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch \
				$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BIN)-$$goos-$$goarch$$ext ./cmd/$(BIN) || exit 1; \
		done; \
	done
	@sha256sum $(DIST)/* > $(DIST)/checksums.txt

docker:
	docker build -t $(BIN):$(VERSION) .

check: fmtcheck vet race build
	./bin/$(BIN) version

clean:
	rm -rf bin $(DIST) coverage.out
