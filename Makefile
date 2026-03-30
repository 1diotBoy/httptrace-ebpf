GO ?= go
GOCACHE ?= /tmp/go-build

.PHONY: generate build test

generate:
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) GOPROXY=off GOSUMDB=off $(GO) generate ./internal/bpfgen

build: generate
	mkdir -p $(GOCACHE) bin
	GOCACHE=$(GOCACHE) CGO_ENABLED=0 GOPROXY=off GOSUMDB=off $(GO) build -trimpath -ldflags '-s -w' -o bin/httptrace ./cmd/httptrace

test:
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) GOPROXY=off GOSUMDB=off $(GO) test ./...
