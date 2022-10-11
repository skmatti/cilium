package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
)

// bpfSFCFlowListCmd represents the bpf_sfcflow_list command
var (
	bpfSFCFlowListCmd = &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List service steering flow tracking entries",
		Run: func(cmd *cobra.Command, args []string) {
			common.RequireRootPrivilege("cilium bpf sfcflow list")
			sfcListFlows()
		},
	}
)

func init() {
	bpfSFCFlowListCmd.Flags().BoolVarP(&timeDiff, "time-diff", "d", false, "print time difference for entries")
	bpfSFCFlowListCmd.Flags().StringVar(&timeDiffClockSourceMode, "time-diff-clocksource-mode", "", "manually set clock source mode (instead of contacting the server)")
	bpfSFCFlowListCmd.Flags().Int64Var(&timeDiffClockSourceHz, "time-diff-clocksource-hz", 250, "manually set clock source Hz")
	bpfSFCFlowCmd.AddCommand(bpfSFCFlowListCmd)
	command.AddOutputOption(bpfSFCFlowListCmd)
}

func doDumpFlows(m *bpf.Map) {
	var (
		out         string
		err         error
		clockSource *models.ClockSource
	)

	if timeDiff {
		clockSource, err = getClockSource()
		if err != nil {
			Fatalf("could not determine clocksource: %s", err)
		}
	}

	out, err = sfc.DumpEntriesWithTimeDiff(m, clockSource)
	if err != nil {
		Fatalf("Error while dumping BPF Map: %s", err)
	}
	fmt.Println(out)
}

func sfcListFlows() {
	if command.OutputOption() {
		entries := make(map[string][]string)
		if err := sfc.FlowMapAny4.Dump(entries); err != nil {
			Fatalf("Unable to dump contents of map: %s", err)
		}
		if err := command.PrintOutput(entries); err != nil {
			Fatalf("Unable to generate output: %s", err)
		}
	} else {
		doDumpFlows(sfc.FlowMapAny4)
	}
}
