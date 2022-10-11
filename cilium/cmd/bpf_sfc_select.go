package cmd

import "github.com/spf13/cobra"

var bpfSFCSelectCmd = &cobra.Command{
	Use:   "sfcselect",
	Short: "Manage TrafficSelector entries for service function chaining",
}

func init() {
	bpfCmd.AddCommand(bpfSFCSelectCmd)
}
