.DEFAULT_GOAL := build

BUILD_VAR_PREFIX := github.com/prometheus/common/version
BUILD_USER := $(shell id -u -n)@$(shell hostname)
BUILD_DATE := $(shell date --iso-8601=seconds)

ifeq (yes,$(shell which git > /dev/null && test -e .git && echo yes))
BUILD_VERSION := $(shell git describe --tags)
BUILD_BRANCH := $(shell git rev-parse --abbrev-ref HEAD)
BUILD_REVISION := $(shell git rev-parse --short HEAD)
else
BUILD_VERSION := unknown
BUILD_BRANCH := unknown
BUILD_REVISION := unknown
endif

GO_LDFLAGS_VARS := -X $(BUILD_VAR_PREFIX).Version=$(BUILD_VERSION) \
	-X $(BUILD_VAR_PREFIX).Branch=$(BUILD_BRANCH) \
	-X $(BUILD_VAR_PREFIX).Revision=$(BUILD_REVISION) \
	-X $(BUILD_VAR_PREFIX).BuildUser=$(BUILD_USER) \
	-X $(BUILD_VAR_PREFIX).BuildDate=$(BUILD_DATE)

GO_LDFLAGS := -ldflags="-extldflags "-static" $(GO_LDFLAGS_VARS)"

CLANG_FORMAT_FILES = ${wildcard examples/*.c examples/*.h benchmark/probes/*.c benchmark/probes/*.h}

export CGO_LDFLAGS := -l bpf

.PHONY: lint
lint:
	go mod verify
	golangci-lint run ./...

.PHONY: clang-format-check
clang-format-check:
	clang-format --dry-run --verbose -Werror $(CLANG_FORMAT_FILES)

.PHONY: test
test:
	go test -v ./...

.PHONY: build
build:
	go build -o ebpf_exporter -v $(GO_LDFLAGS) ./cmd/ebpf_exporter

syscalls:
	go run ./scripts/mksyscalls --strace.version v6.4
