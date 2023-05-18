# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

include ../Makefile.defs

TARGET := global-peer

all: $(TARGET)

.PHONY: all $(TARGET)

$(TARGET): ../Makefile ../Makefile.defs Makefile
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $(TARGET)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGET)
	$(QUIET)$(GO_CLEAN)
