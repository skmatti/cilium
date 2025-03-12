package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/egressmap"
)

const (
	egressTimeoutsListUsage = "List egress timeout entries."
)

type egressTimeouts struct {
	SourceIP           string
	DestCIDR           string
	ConnectionTimeouts string
}

/*
This command allows you to see which external connections have specific timeout
configurations applied to them. Each entry represents a rule that defines how
long a connection to a particular destination CIDR originating from a specific
source IP will remain active in the absence of traffic.

The output will show a list of these entries, including:
  - Source IP: The internal IP address for which the timeout rule is configured.
  - Destination CIDR: The external network range or specific IP address this rule applies to.
  - Connection Timeouts: The configured timeout values for connections matching this rule.
*/
var bpfEgressTimeoutsListCmd = &cobra.Command{
	Use:     "timeouts",
	Aliases: []string{"timeouts"},
	Short:   "List egress timeout entries",
	Long:    egressTimeoutsListUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf egress timeouts")

		egressTimeoutsMap, err := egressmap.OpenPinnedEgressTimeoutsMap()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "Cannot find egress timeouts bpf maps")
				return
			}

			Fatalf("Cannot open egress timeouts bpf maps: %s", err)
		}

		bpfEgressTimeoutsList := []egressTimeouts{}
		parse := func(key *egressmap.EgressPolicyKey4, val *egressmap.EgressTimeoutsVal4) {
			bpfEgressTimeoutsList = append(bpfEgressTimeoutsList, egressTimeouts{
				SourceIP:           key.GetSourceIP().String(),
				DestCIDR:           key.GetDestCIDR().String(),
				ConnectionTimeouts: val.GetTimeouts().String(),
			})
		}

		if err := egressTimeoutsMap.IterateWithCallback(parse); err != nil {
			Fatalf("Error dumping contents of egress timeouts map: %s\n", err)
		}

		if command.OutputOption() {
			if err := command.PrintOutput(bpfEgressTimeoutsList); err != nil {
				Fatalf("error getting output of map in %s: %s\n", command.OutputOptionString(), err)
			}
			return
		}

		if len(bpfEgressTimeoutsList) == 0 {
			fmt.Fprintf(os.Stderr, "No entries found.\n")
		} else {
			printEgressTimeoutsList(bpfEgressTimeoutsList)
		}
	},
}

func printEgressTimeoutsList(egressTimeoutsList []egressTimeouts) {
	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

	fmt.Fprintln(w, "Source IP\tDestination CIDR\tConnection Timeouts")
	for _, ep := range egressTimeoutsList {
		fmt.Fprintf(w, "%s\t%s\t%s\n", ep.SourceIP, ep.DestCIDR, ep.ConnectionTimeouts)
	}

	w.Flush()
}

func init() {
	BPFEgressCmd.AddCommand(bpfEgressTimeoutsListCmd)
	command.AddOutputOption(bpfEgressTimeoutsListCmd)
}
