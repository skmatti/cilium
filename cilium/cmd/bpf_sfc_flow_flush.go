// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
)

// bpfSFCFlowFlushCmd represents the bpf_sfcflow_flush command
var bpfSFCFlowFlushCmd = &cobra.Command{
	Use:   "flush",
	Short: "Flush all service steering flow tracking entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sfcflow flush")
		deleted := sfc.FlushFlow()
		fmt.Printf("Flushed %d entries\n", deleted)
	},
}

func init() {
	bpfSFCFlowCmd.AddCommand(bpfSFCFlowFlushCmd)
}
