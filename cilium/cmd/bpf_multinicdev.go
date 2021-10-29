package cmd

import (
	"github.com/spf13/cobra"
)

// bpfMultiNICDevCmd represents the bpf command
var bpfMultiNICDevCmd = &cobra.Command{
	Use:   "multinicdev",
	Short: "Manage the devices of L2 multinic endpoints",
}

func init() {
	bpfCmd.AddCommand(bpfMultiNICDevCmd)
}
