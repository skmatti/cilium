package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/multinicdev"

	"github.com/spf13/cobra"
)

const (
	multiNICDevUpdateUsage = "Create/Update multinicdev entry.\n"
)

var bpfMultiNICDevUpdateCmd = &cobra.Command{
	Args:    cobra.ExactArgs(3),
	Use:     "update",
	Short:   "Update multinicdev entries",
	Aliases: []string{"add"},
	Long:    multiNICDevUpdateUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf multinicdev update <mac> <ep_id> <ifindex>")

		m, err := multinicdev.ParseMAC(args[0])
		if err != nil {
			Fatalf(err.Error())
		}

		epID, err := strconv.ParseUint(args[1], 10, 16)
		if err != nil {
			Fatalf("Unable to parse endpoint ID %q: %v", args[1], err)
		}

		ifindex, err := strconv.ParseUint(args[2], 10, 32)
		if err != nil {
			Fatalf("Unable to parse ifindex %q: %v", args[2], err)
		}

		key := multinicdev.NewKey(m)
		value := &multinicdev.MultiNICDevInfo{
			EndpointID: uint16(epID),
			IfIndex:    uint32(ifindex),
		}
		if err := multinicdev.Map.Update(&key, value); err != nil {
			fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	bpfMultiNICDevCmd.AddCommand(bpfMultiNICDevUpdateCmd)
}
