package cmd

import (
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/spf13/cobra"
)

var bpfSFCPathAddCmd = &cobra.Command{
	Args:  cobra.ExactArgs(3),
	Use:   "add <spi> <si> <sf_ip>",
	Short: "Add/update service function path entry",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf sfcpath add")

		pathKey := ParsePath(args[0], args[1])

		ip := net.ParseIP(args[2])
		if ip == nil {
			Fatalf("Unable to parse SF IP %q", args[2])
		}
		pathEntry := sfc.NewPathEntry(ip)

		if err := sfc.PathMap.Update(pathKey, pathEntry); err != nil {
			Fatalf("Failed to update map: %v", err)
		}
	},
}

func ParsePath(spiStr, siStr string) *sfc.PathKey {
	spi, err := strconv.ParseUint(spiStr, 10, 24)
	if err != nil {
		Fatalf("Unable to parse SPI %q: %v", spiStr, err)
	}
	si, err := strconv.ParseUint(siStr, 10, 8)
	if err != nil {
		Fatalf("Unable to parse SI %q: %v", siStr, err)
	}
	pathKey, err := sfc.NewPathKey(uint32(spi), uint8(si))
	if err != nil {
		Fatalf("%v", err)
	}
	return pathKey
}

func init() {
	bpfSFCPathCmd.AddCommand(bpfSFCPathAddCmd)
}
