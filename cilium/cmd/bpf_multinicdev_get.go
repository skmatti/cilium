package cmd

import (
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/multinicdev"
	"golang.org/x/sys/unix"

	"github.com/spf13/cobra"
)

const (
	multiNICDevGetUsage = "Get multinicdev entries using device MAC addresses.\n"
)

var bpfMultiNICDevGetCmd = &cobra.Command{
	Args:    cobra.ExactArgs(1),
	Use:     "get",
	Short:   "Get multinicdev entries",
	Aliases: []string{"lookup"},
	Long:    multiNICDevGetUsage,
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf multinicdev get <mac>")

		m, err := multinicdev.ParseMAC(args[0])
		if err != nil {
			Fatalf(err.Error())
		}

		key := multinicdev.NewKey(m)
		value, err := multinicdev.Map.Lookup(&key)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				Fatalf("element not found")
			}
			Fatalf("error lookup contents of map: %s\n", err)
		}

		fmt.Println(value.String())
	},
}

func init() {
	bpfMultiNICDevCmd.AddCommand(bpfMultiNICDevGetCmd)
}
