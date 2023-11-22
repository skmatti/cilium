package cmd

import (
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
