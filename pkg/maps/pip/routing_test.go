package pip

import (
	"net"
	"testing"
)

func TestCIDRKey(t *testing.T) {
	tests := []struct {
		name     string
		cidrStr  string
		expected string
	}{
		{
			name:    "IPv4-32",
			cidrStr: "10.241.4.100/32",
		},
		{
			name:    "IPv6-128",
			cidrStr: "fe00::/128",
		},
		{
			name:    "IPv6-64",
			cidrStr: "fe00::/64",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, cidr, err := net.ParseCIDR(tc.cidrStr)
			if err != nil {
				t.Fatalf("invalid cidr input %q: %s", tc.cidrStr, err)
			}
			key := NewCIDRKey(cidr)
			if got, want := key.String(), tc.cidrStr; got != want {
				t.Fatalf("NewCIDRKey() got %q, but want %q", got, want)
			}
		})
	}
}
