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
	pathKey, err := sfc.NewPathKey(ParseSPI(spiStr), ParseSI(siStr))
	if err != nil {
		Fatalf("Failed to create path key: %v", err)
	}
	return pathKey
}

func ParseSPI(spiStr string) uint32 {
	spi, err := strconv.ParseUint(spiStr, 10, 24)
	if err != nil {
		Fatalf("Unable to parse SPI %q: %v", spiStr, err)
	}
	return uint32(spi)
}

func ParseSI(siStr string) uint8 {
	si, err := strconv.ParseUint(siStr, 10, 8)
	if err != nil {
		Fatalf("Unable to parse SI %q: %v", siStr, err)
	}
	return uint8(si)
}

func init() {
	bpfSFCPathCmd.AddCommand(bpfSFCPathAddCmd)
}
