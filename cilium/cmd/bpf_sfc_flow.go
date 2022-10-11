package cmd

import (
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/cilium/cilium/pkg/option"
	"github.com/spf13/cobra"
)

var bpfSFCFlowCmd = &cobra.Command{
	Use:   "sfcflow",
	Short: "Service Steering flow tracking tables",
}

func init() {
	sfc.InitFlowMap(option.CTMapEntriesGlobalTCPDefault)
	bpfCmd.AddCommand(bpfSFCFlowCmd)
}
