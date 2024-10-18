package multinetworking

import (
	"fmt"
	"net"
	"testing"
)

func TestNewHostInterfaceKey(t *testing.T) {
	tests := []struct {
		name     string
		ifIndex  uint32
		cidrStr  string
		expected string
	}{
		{
			name:    "IPv4-21",
			ifIndex: 100,
			cidrStr: "10.241.0.0/21",
		},
		{
			name:    "IPv4-32",
			ifIndex: 101,
			cidrStr: "10.241.4.100/32",
		},
		{
			name:    "IPv6-128",
			ifIndex: 102,
			cidrStr: "fe00::/128",
		},
		{
			name:    "IPv6-64",
			ifIndex: 103,
			cidrStr: "fe00::/64",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, cidr, err := net.ParseCIDR(tc.cidrStr)
			if err != nil {
				t.Fatalf("invalid cidr input %q: %s", tc.cidrStr, err)
			}
			key := NewHostDevRoutingKey(tc.ifIndex, cidr)
			got := key.String()
			want := fmt.Sprintf("ifindex=%d, cidr=%s", tc.ifIndex, tc.cidrStr)
			if got != want {
				t.Fatalf("NewCIDRKey() got %q, but want %q", got, want)
			}
		})
	}
}
