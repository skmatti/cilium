package cmd

import (
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/multinicdev"

	"github.com/spf13/cobra"
)

const (
	multiNICDevDeleteUsage = "Delete multinicdev entries using MAC address.\n"
)

var bpfMultiNICDevDeleteCmd = &cobra.Command{
	Args:  cobra.ExactArgs(1),
	Use:   "delete",
	Short: "Delete multinicdev entries",
	Long:  multiNICDevDeleteUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf multinicdev delete <mac>")

		m, err := multinicdev.ParseMAC(args[0])
		if err != nil {
			Fatalf(err.Error())
		}

		key := multinicdev.NewKey(m)

		if err := multinicdev.Map.Delete(&key); err != nil {
			Fatalf("error deleting contents of map: %s\n", err)
		}
	},
}

func init() {
	bpfMultiNICDevCmd.AddCommand(bpfMultiNICDevDeleteCmd)
}
