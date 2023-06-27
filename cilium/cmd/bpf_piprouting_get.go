package cmd

import (
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/pip"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var persistentIPRoutingGetCmd = &cobra.Command{
	Args:    cobra.ExactArgs(1),
	Use:     "get",
	Short:   "Get persistent ip routing entries",
	Aliases: []string{"lookup"},
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf piprouting get <cidr>")

		cidr := ParseCIDR(args[0])
		key := pip.NewCIDRKey(cidr)
		value, err := pip.RoutingMap.Lookup(key)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				Fatalf("element not found")
			}
			Fatalf("error lookup contents of map: %s\n", err)
		}
		fmt.Println(value.String())
	},
}

func init() {
	bpfPersistentIPRoutingCmd.AddCommand(persistentIPRoutingGetCmd)
}
