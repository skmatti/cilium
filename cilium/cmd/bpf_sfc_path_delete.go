package cmd

import (
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/spf13/cobra"
)

var bpfSFCPathDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(2),
	Use:   "delete <spi> <si>",
	Short: "Delete service function path entry",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sfcpath delete")

		pathKey := ParsePath(args[0], args[1])
		if err := sfc.PathMap.Delete(pathKey); err != nil {
			Fatalf("Failed to update map: %v", err)
		}
	},
}

func init() {
	bpfSFCPathCmd.AddCommand(bpfSFCPathDeleteCmd)
}
