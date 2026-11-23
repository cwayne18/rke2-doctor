BINARY := rke2-doctor
PKG := ./cmd/rke2-doctor
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test lint fmt clean

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) $(PKG)

test:
	go test ./... -race -cover

lint:
	go vet ./...
	@fmt_out="$$(gofmt -l .)"; \
	if [ -n "$$fmt_out" ]; then \
		echo "not gofmt-formatted:"; echo "$$fmt_out"; exit 1; \
	fi

clean:
	rm -rf bin
