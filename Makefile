.PHONY: build test vet clean

BINARY = netaudit
MODULE = github.com/velasco-jp/netaudit

build:
	go build -o $(BINARY) ./cmd/netaudit/

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY) netaudit-*

# Cross-compile for releases
release:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 ./cmd/netaudit/
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 ./cmd/netaudit/
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY)-darwin-amd64 ./cmd/netaudit/
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY)-darwin-arm64 ./cmd/netaudit/
	GOOS=windows GOARCH=amd64 go build -o $(BINARY)-windows-amd64.exe ./cmd/netaudit/

.DEFAULT_GOAL := build
