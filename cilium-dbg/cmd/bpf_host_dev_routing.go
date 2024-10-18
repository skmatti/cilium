package cmd

import (
	"net"

	"github.com/spf13/cobra"
)

// bpfHostDevRoutingCmd represents the bpf command
var bpfHostDevRoutingCmd = &cobra.Command{
	Use:   "hostdevrouting",
	Short: "Manage host device bpf based routing",
}

func init() {
	BPFCmd.AddCommand(bpfHostDevRoutingCmd)
}

func ParseCIDR(cidrStr string) *net.IPNet {
	_, cidr, err := net.ParseCIDR(cidrStr)
	if err != nil {
		Fatalf("Unable to parse CIDR %q: %v", cidrStr, err)
	}
	return cidr
}
