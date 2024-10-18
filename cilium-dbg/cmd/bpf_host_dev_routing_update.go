package cmd

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/multinetworking"

	"github.com/spf13/cobra"
)

const (
	hostDevRoutingUsage = "Create/Update bpf host device routing entry.\n"
)

var bpfHostDevRoutingUpdateCmd = &cobra.Command{
	Args:    cobra.ExactArgs(3),
	Use:     "update <cidr> <ifindex> <next_hop_addr>",
	Short:   "Update host device bpf routing entries",
	Aliases: []string{"add"},
	Long:    hostDevRoutingUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf hostdevrouting update")

		cidr := ParseCIDR(args[0])
		ifIndex, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not parse ifindex: %s\n", err)
			os.Exit(1)
		}

		nextHopAddr := args[2]
		ip := net.ParseIP(nextHopAddr)
		if ip == nil {
			fmt.Fprintf(os.Stderr, "failed to parse next hop address")
			os.Exit(1)
		}

		key := multinetworking.NewHostDevRoutingKey(uint32(ifIndex), cidr)
		value := multinetworking.NewHostDevRoutingEntry(ip)
		if err := multinetworking.HostDevRoutingMap.Update(key, value); err != nil {
			fmt.Fprintf(os.Stderr, "error updating contents of map: %s\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	bpfHostDevRoutingCmd.AddCommand(bpfHostDevRoutingUpdateCmd)
}
