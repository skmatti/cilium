# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

QUIET ?= @
GO_BUILD_SLIM := go build -mod=vendor
GO_BUILD_IMAGE := golang:1.20
IMAGE_VERSION ?= latest
DOCKER_IMAGE_TAG ?= $(IMAGE_VERSION)

TARGET := anet-agent
WIN_TARGET := anet-agent.exe

# Borrow multi-arch build support from the main Makefile.
include ../Makefile.defs
include ../Makefile.docker

all: linux windows

linux: $(TARGET)__linux_$(ARCH)

windows: $(WIN_TARGET)

.PHONY: all linux windows

$(TARGET)__linux_$(ARCH):
	$(QUIET)docker run \
		-i \
		--rm \
		-v $$(pwd)/../pkg:/cilium/pkg \
		-v $$(pwd)/../api:/cilium/api \
		-v $$(pwd)/../slim-daemon:/cilium/slim-daemon \
		-v $$(pwd)/../go.mod:/cilium/go.mod \
		-v $$(pwd)/../go.sum:/cilium/go.sum \
		-v $$(pwd)/../vendor:/cilium/vendor \
		-w /cilium/slim-daemon \
		-v $$(pwd):/out \
		--env CGO_ENABLED=0 \
		--env GOOS=linux \
		--env GOARCH=$(ARCH) \
		$(GO_BUILD_IMAGE) \
		$(GO_BUILD_SLIM) -o /out/"$@"

$(WIN_TARGET):
	sed -i '/\+build \!windows/'d ../vendor/github.com/miekg/dns/udp.go
	$(QUIET)GOOS=windows $(GO_BUILD_SLIM) -o $(WIN_TARGET)
	git checkout ../vendor/github.com/miekg/dns/udp.go

.PHONY: $(TARGET)__linux_$(ARCH) $(WIN_TARGET)

clean:
	$(QUIET)rm -f $(TARGET)__linux_* $(WIN_TARGET)

.PHONY: clean

windows-image:
	$(QUIET)docker build -t anet-agent-windows:$(IMAGE_VERSION) -f Dockerfile.windows ..

linux-image: $(TARGET)__linux_$(ARCH)
	$(QUIET)docker buildx build \
		$(DOCKER_FLAGS) \
		--build-arg BIN="$<" \
		-t $(IMAGE_REPOSITORY)/slim-daemon/anet-agent:$(DOCKER_IMAGE_TAG) \
		-f Dockerfile.ubuntu \
		.

.PHONY: windows-image linux-image
