// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"github.com/cilium/cilium/global-peer/cmd"
	"github.com/cilium/cilium/pkg/logging"
)

func main() {
	if err := cmd.New().Execute(); err != nil {
		logging.DefaultLogger.Fatalf("command failed: %v", err)
	}
}
