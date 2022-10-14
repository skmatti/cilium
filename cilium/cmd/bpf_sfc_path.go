package cmd

import "github.com/spf13/cobra"

var bpfSFCPathCmd = &cobra.Command{
	Use:   "sfcpath",
	Short: "Manage (SPI, SI) <-> ServiceFunction IP mappings",
}

func init() {
	bpfCmd.AddCommand(bpfSFCPathCmd)
}
