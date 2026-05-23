.PHONY: build test vet clean

BINARY = nyx
MODULE = github.com/velasco-jp/nyx

build:
	go build -o $(BINARY) ./cmd/nyx/

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY) nyx-*

# Cross-compile for releases
release:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 ./cmd/nyx/
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 ./cmd/nyx/
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY)-darwin-amd64 ./cmd/nyx/
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY)-darwin-arm64 ./cmd/nyx/
	GOOS=windows GOARCH=amd64 go build -o $(BINARY)-windows-amd64.exe ./cmd/nyx/

.DEFAULT_GOAL := build
