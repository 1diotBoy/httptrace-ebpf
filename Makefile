GO ?= go
GOCACHE ?= /tmp/go-build
GO_BUILD_FLAGS ?= -trimpath -tags 'netgo osusergo' -ldflags '-s -w'
STATIC_ENV ?= CGO_ENABLED=0 GOPROXY=off GOSUMDB=off
HOST_GOOS ?= $(shell $(GO) env GOHOSTOS)
HOST_GOARCH ?= $(shell $(GO) env GOHOSTARCH)
GOOS ?= linux
GOARCH ?= $(shell $(GO) env GOARCH)
GOARM ?= 7
OUTPUT ?= bin/httptrace

ifeq ($(GOARCH),arm)
GO_CROSS_ENV := GOOS=$(GOOS) GOARCH=$(GOARCH) GOARM=$(GOARM)
OUTPUT_SUFFIX := $(GOOS)-$(GOARCH)v$(GOARM)
else
GO_CROSS_ENV := GOOS=$(GOOS) GOARCH=$(GOARCH)
OUTPUT_SUFFIX := $(GOOS)-$(GOARCH)
endif

ifneq ($(origin OUTPUT), command line)
ifneq ($(origin OUTPUT), environment)
OUTPUT := bin/httptrace-$(OUTPUT_SUFFIX)
endif
endif

.PHONY: generate build build-static build-amd64 build-arm64 build-arm clean-generated test

generate:
	mkdir -p $(GOCACHE)
	rm -f internal/bpfgen/httptrace_bpfel.go internal/bpfgen/httptrace_bpfel.o
	rm -f internal/bpfgen/httptracelegacy_bpfel.go internal/bpfgen/httptracelegacy_bpfel.o
	rm -f internal/bpfgen/httptrace_x86_bpfel.go internal/bpfgen/httptrace_x86_bpfel.o
	rm -f internal/bpfgen/httptrace_arm64_bpfel.go internal/bpfgen/httptrace_arm64_bpfel.o
	rm -f internal/bpfgen/httptracelegacy_x86_bpfel.go internal/bpfgen/httptracelegacy_x86_bpfel.o
	rm -f internal/bpfgen/httptracelegacy_arm64_bpfel.go internal/bpfgen/httptracelegacy_arm64_bpfel.o
	GOCACHE=$(GOCACHE) GOOS=$(HOST_GOOS) GOARCH=$(HOST_GOARCH) GOPROXY=off GOSUMDB=off $(GO) generate ./internal/bpfgen

build: generate
	mkdir -p $(GOCACHE) bin
	GOCACHE=$(GOCACHE) $(STATIC_ENV) $(GO_CROSS_ENV) $(GO) build $(GO_BUILD_FLAGS) -o $(OUTPUT) ./cmd/httptrace

build-static: build

build-amd64:
	$(MAKE) build GOOS=linux GOARCH=amd64 OUTPUT=bin/httptrace-linux-amd64

build-arm64:
	$(MAKE) build GOOS=linux GOARCH=arm64 OUTPUT=bin/httptrace-linux-arm64

build-arm:
	@echo "当前环境缺少 ARM32 交叉编译所需的内核头文件/sysroot；已稳定支持 amd64 和 arm64。"
	@echo "如需 armv7，请先安装 /usr/arm-linux-gnueabihf/include 后再扩展 bpf2go 目标。"
	@exit 1

clean-generated:
	rm -f internal/bpfgen/httptrace_x86_bpfel.go internal/bpfgen/httptrace_x86_bpfel.o
	rm -f internal/bpfgen/httptrace_arm64_bpfel.go internal/bpfgen/httptrace_arm64_bpfel.o
	rm -f internal/bpfgen/httptracelegacy_x86_bpfel.go internal/bpfgen/httptracelegacy_x86_bpfel.o
	rm -f internal/bpfgen/httptracelegacy_arm64_bpfel.go internal/bpfgen/httptracelegacy_arm64_bpfel.o
	rm -f internal/bpfgen/httptrace_bpfel.go internal/bpfgen/httptrace_bpfel.o
	rm -f internal/bpfgen/httptracelegacy_bpfel.go internal/bpfgen/httptracelegacy_bpfel.o

test:
	mkdir -p $(GOCACHE)
	GOCACHE=$(GOCACHE) GOPROXY=off GOSUMDB=off $(GO) test ./...
