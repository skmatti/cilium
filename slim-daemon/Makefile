# Copyright 2017-2020 Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

QUIET := @
GO_BUILD := go build -mod=vendor
IMAGE_VERSION ?= latest

TARGET := anet-agent
WIN_TARGET := anet-agent.exe

all: $(TARGET) $(WIN_TARGET)

windows: $(WIN_TARGET)

linux: $(TARGET)

.PHONY: all linux windows $(TARGET) $(WIN_TARGET)

$(TARGET):
	$(QUIET)$(GO_BUILD) -o $(TARGET)

$(WIN_TARGET):
	sed -i '/\+build \!windows/'d ../vendor/github.com/miekg/dns/udp.go
	$(QUIET)GOOS=windows $(GO_BUILD) -o $(WIN_TARGET)
	git checkout ../vendor/github.com/miekg/dns/udp.go

clean:
	$(QUIET)rm -f $(TARGET) $(WIN_TARGET)

.PHONY: clean

windows-image:
	$(QUIET)docker build -t anet-agent-windows:$(IMAGE_VERSION) -f Dockerfile.windows ..

linux-image:
	$(QUIET)docker build -t anet-agent:$(IMAGE_VERSION) -f Dockerfile.ubuntu ..

.PHONY: windows-image
