//go:build linux

package node

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

func setupInf(name string, ips ...string) error {
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: name,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(dummy); err != nil {
		netlink.LinkDel(dummy)
		return err
	}

	for _, ipStr := range ips {

		ip := net.ParseIP(ipStr)
		if ip == nil {
			netlink.LinkDel(dummy)
			return fmt.Errorf("invalid IP : %v", ipStr)
		}
		var mask net.IPMask
		if ip.To4() != nil {
			mask = net.CIDRMask(32, 32)
		} else {
			mask = net.CIDRMask(128, 128)
		}
		ipnet := &net.IPNet{IP: ip, Mask: mask}
		addr := &netlink.Addr{IPNet: ipnet, Scope: int(netlink.SCOPE_UNIVERSE)}
		if err := netlink.AddrAdd(dummy, addr); err != nil {
			netlink.LinkDel(dummy)
			return err
		}
	}
	return nil
}

func removeInf(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get link by name %s: %w", name, err)
	}
	if err := netlink.LinkDel(l); err != nil {
		return fmt.Errorf("failed to delete link %s: %w", name, err)
	}
	return nil
}

func TestFirstV4GlobalAddrOnInf(t *testing.T) {
	testutils.PrivilegedTest(t)
	testCases := []struct {
		name     string
		infNames []string
		infIPs   [][]string
		input    string
		want     string
		wantErr  bool
		desc     string
	}{
		{
			name:     "Invalid Interface",
			infNames: []string{"test-eth0", "test-eth1"},
			infIPs:   [][]string{{"10.0.0.1"}, {"192.168.0.1"}},
			input:    "",
			wantErr:  true,
			want:     "",
			desc:     "Empty interface name should return error",
		},
		{
			name:     "Interface not found",
			infNames: []string{"test-eth0", "test-eth1"},
			infIPs:   [][]string{{"10.0.0.1"}, {"192.168.0.1"}},
			input:    "dummy-inf",
			wantErr:  true,
			desc:     "Non-existent interface should return error",
		},
		{
			name:     "Valid IP",
			infNames: []string{"test-eth0", "test-eth1"},
			infIPs:   [][]string{{"10.0.0.1"}, {"192.168.0.1"}},
			input:    "test-eth1",
			want:     "192.168.0.1",
			desc:     "Interface with valid IP, should return valid IP",
		},
		{
			name:     "Valid IP, multiple IPs",
			infNames: []string{"test-eth0", "test-eth1"},
			infIPs:   [][]string{{"10.0.0.1"}, {"169.254.0.0", "fd00::1", "10.0.0.2", "192.168.0.1", "172.16.0.1"}},
			input:    "test-eth1",
			want:     "10.0.0.2", // Because of the order added.  See firstGlobalAddr.
			desc:     "Interface with multiple valid IPs, should return first added valid IP",
		},
		{
			name:     "No global IP on interface",
			infNames: []string{"test-eth0", "test-eth1"},
			infIPs:   [][]string{{"10.0.0.1"}, {"169.254.0.0"}}, // Link-local, not global.
			input:    "test-eth1",
			wantErr:  true,
			want:     "",
			desc:     "Interface with no valid global IP, should return error",
		},
		{
			name:     "No IPv4 address on interface",
			infNames: []string{"test-eth0", "test-eth1"},
			infIPs:   [][]string{{"10.0.0.1"}, {"fd00::1"}},
			input:    "test-eth1",
			wantErr:  true,
			want:     "",
			desc:     "Interface with no IPv4 address, should return error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			testNetNS, cleanupNetNS := setupNetNS(t, "test-netns")
			defer cleanupNetNS()

			err := testNetNS.Do(func(_ ns.NetNS) error {
				for i, infName := range tc.infNames {
					err := setupInf(infName, tc.infIPs[i]...)
					require.NoError(t, err, "Failed to set up interface %s", infName)

					defer func(infName string) {
						err := removeInf(infName)
						require.NoError(t, err, "Failed to remove interface %s", infName)
					}(infName)
				}

				got, err := FirstV4GlobalAddrOnInf(tc.input)

				if tc.wantErr {
					require.Error(t, err)
				} else {
					require.NoError(t, err)
					require.Equal(t, tc.want, got)
				}
				return nil
			})
			require.NoError(t, err)

		})
	}
}

func setupNetNS(t *testing.T, nsName string) (ns.NetNS, func()) {
	t.Helper()

	netns0, err := netns.ReplaceNetNSWithName(nsName)
	require.NoError(t, err)
	require.NotNil(t, netns0)

	return netns0, func() {
		require.NoError(t, netns.RemoveNetNSWithName(nsName))
	}
}
