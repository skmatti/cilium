package cmd

import "github.com/spf13/cobra"

var bpfSFCCIDRCmd = &cobra.Command{
	Use:   "sfccidr",
	Short: "Manage IP <-> CIDR mappings for service function chaining",
}

func init() {
	bpfCmd.AddCommand(bpfSFCCIDRCmd)
}
