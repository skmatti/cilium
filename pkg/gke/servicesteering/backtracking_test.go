package servicesteering

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/google/go-cmp/cmp"
)

func Test_protoCoverage(t *testing.T) {
	tests := []struct {
		proto      u8proto.U8proto
		portNumber uint16
		want       bool
	}{
		{want: true, proto: u8proto.TCP, portNumber: 80},
		{want: false, proto: u8proto.TCP, portNumber: 80},
		{want: true, proto: u8proto.TCP, portNumber: 8080},
		{want: true, proto: u8proto.UDP, portNumber: 8080},
		{want: true, proto: u8proto.UDP, portNumber: 0},
		{want: false, proto: u8proto.UDP, portNumber: 0},
		{want: false, proto: u8proto.UDP, portNumber: 53},
	}
	cov := protoCoverage{}
	for _, tt := range tests {
		if got := cov.add(uint8(tt.proto), tt.portNumber); got != tt.want {
			t.Errorf("coverage.add(%s, %d) = %v, want %v", tt.proto, tt.portNumber, got, tt.want)
		}
	}
}

func Test_fallbackEntries(t *testing.T) {
	tests := []struct {
		name      string
		selectors map[sfc.SelectKey]sfc.PathKey
		want      map[sfc.SelectKey]sfc.PathKey
	}{
		{
			name: "no fallback",
			selectors: map[sfc.SelectKey]sfc.PathKey{
				selectKey("10.0.0.0/24", u8proto.TCP, 80):   path(1),
				selectKey("10.0.0.0/24", u8proto.TCP, 8080): path(2),
			},
			want: map[sfc.SelectKey]sfc.PathKey{},
		},
		{
			name: "single port",
			selectors: map[sfc.SelectKey]sfc.PathKey{
				selectKey("10.0.0.0/24", u8proto.TCP, 80):   path(1), // should fallback to 2 for 8080/TCP
				selectKey("10.0.0.0/16", u8proto.TCP, 8080): path(2),
			},
			want: map[sfc.SelectKey]sfc.PathKey{
				selectKey("10.0.0.0/24", u8proto.TCP, 8080): path(2),
			},
		},
		{
			name: "non-overlapping CIDRs",
			selectors: map[sfc.SelectKey]sfc.PathKey{
				selectKey("10.0.0.0/24", u8proto.TCP, 80):   path(1),
				selectKey("20.0.0.0/16", u8proto.UDP, 8080): path(2),
				selectKey("40.0.0.0/16", u8proto.TCP, 443):  path(3), // should fallback to 4 for 8080/TCP
				selectKey("40.0.0.0/8", u8proto.TCP, 8080):  path(4),
				selectKey("30.0.0.0/20", u8proto.TCP, 0):    path(5),
				selectKey("30.0.0.0/22", u8proto.UDP, 0):    path(6), // should fallback to 5 for all TCP
			},
			want: map[sfc.SelectKey]sfc.PathKey{
				selectKey("40.0.0.0/16", u8proto.TCP, 8080): path(4),
				selectKey("30.0.0.0/22", u8proto.TCP, 0):    path(5),
			},
		},
		{
			name: "different protocols",
			selectors: map[sfc.SelectKey]sfc.PathKey{
				selectKey("10.0.0.0/24", u8proto.TCP, 80): path(1), // should fallback to 2 for 80/UDP
				selectKey("10.0.0.0/16", u8proto.UDP, 80): path(2),
			},
			want: map[sfc.SelectKey]sfc.PathKey{
				selectKey("10.0.0.0/24", u8proto.UDP, 80): path(2),
			},
		},
		{
			name: "all ports",
			selectors: map[sfc.SelectKey]sfc.PathKey{
				selectKey("10.0.0.0/24", u8proto.TCP, 80):   path(1), // should fallback to 3 for all UDP and TCP
				selectKey("10.0.0.0/16", u8proto.TCP, 8080): path(2),
				selectKey("10.0.0.0/20", u8proto.TCP, 0):    path(3),
				selectKey("10.0.0.0/20", u8proto.UDP, 0):    path(3),
			},
			want: map[sfc.SelectKey]sfc.PathKey{
				selectKey("10.0.0.0/24", u8proto.TCP, 0): path(3),
				selectKey("10.0.0.0/24", u8proto.UDP, 0): path(3),
			},
		},
		{
			name: "empty",
			want: map[sfc.SelectKey]sfc.PathKey{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fallbackEntries(tt.selectors, true)
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("fallbackEntries() returns unexpected output (-got, +want):\n%s", diff)
			}
		})
	}
}

func selectKey(cidr string, proto u8proto.U8proto, port uint16) sfc.SelectKey {
	_, parsedCIDR, _ := net.ParseCIDR(cidr)
	return *sfc.NewSelectKey(0, true, *parsedCIDR, port, proto)
}

func path(spi uint32) sfc.PathKey {
	path, _ := sfc.NewPathKey(spi, 0)
	return *path
}
