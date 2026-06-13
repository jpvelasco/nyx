.PHONY: build test vet clean release lint gosec check

BINARY = nyx

build:
	go build -o $(BINARY) ./cmd/nyx/

test:
	go test ./...

vet:
	go vet ./...

gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@latest ./...

check: gosec vet test build

clean:
	rm -f $(BINARY) nyx-* nyx.exe

lint:
	golangci-lint run ./...

# VERSION can be overridden: make release VERSION=v0.2.0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X github.com/jpvelasco/nyx/internal/version.Version=$(VERSION)"

# Cross-compile for releases (run on any OS with Go)
release:
	@echo "Building release version: $(VERSION)"
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64          ./cmd/nyx/
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64          ./cmd/nyx/
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-darwin-amd64         ./cmd/nyx/
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-darwin-arm64         ./cmd/nyx/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-windows-amd64.exe    ./cmd/nyx/
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-windows-arm64.exe    ./cmd/nyx/
	@echo "Release binaries built for $(VERSION)"

.DEFAULT_GOAL := build
