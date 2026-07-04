BINARY    := ssl-agent
MODULE    := github.com/quietls/agent
VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)

.PHONY: build test clean lint test-agent-docker

test-agent-docker:
	@echo "Running multi-distro agent tests..."
	@docker-test/run-detection-test.sh

build:
	@mkdir -p bin
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/$(BINARY) ./cmd/ssl-agent

test:
	go test ./... -race -count=1

clean:
	rm -rf bin/

lint:
	golangci-lint run ./...
