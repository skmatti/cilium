package cmd

import (
	"github.com/spf13/cobra"
)

// bpfPersistentIPRoutingCmd represents the bpf command
var bpfPersistentIPRoutingCmd = &cobra.Command{
	Use:   "piprouting",
	Short: "Manage the persistent ip routes of L3 multinic endpoints",
}

func init() {
	bpfCmd.AddCommand(bpfPersistentIPRoutingCmd)
}
