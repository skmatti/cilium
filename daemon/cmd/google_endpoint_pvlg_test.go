package cmd

import (
	"fmt"
	"net"
	"runtime"
	"testing"

	cilnetns "github.com/cilium/cilium/pkg/netns"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	macvtapLinkName = "macvtap1"
	macvtapLinkIP   = "172.168.10.1"
	macvtapLinkMask = 24
	remoteNSName    = "test-mn-netns0"
)

// setupMacvtapInRemoteNS creates a new remote network namespace
// and a macvtap interface in the remote ns.
// The function switches the current ns and reverts afterwards.
func setupVethInRemoteNS(t *testing.T) (int, int, string, func() error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	currentNS, err := netns.Get()
	if err != nil {
		t.Fatalf("failed to get current network namespace: %v", err)
	}
	defer netns.Set(currentNS)

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
		PeerName:  "veth1",
	}
	err = netlink.LinkAdd(veth)
	if err != nil {
		t.Fatal(err)
	}
	veth0, err := netlink.LinkByName("veth0")
	if err != nil {
		t.Fatal(err)
	}
	veth1, err := netlink.LinkByName("veth1")
	if err != nil {
		t.Fatal(err)
	}
	_, ipnet, err := net.ParseCIDR("192.168.1.0/24")
	ip1 := net.ParseIP("192.168.1.10")
	addr := &netlink.Addr{IPNet: ipnet}
	err = netlink.LinkSetUp(veth0)
	if err != nil {
		t.Fatal(err)
	}

	netns0, err := cilnetns.ReplaceNetNSWithName(remoteNSName)
	if err != nil {
		t.Fatal(err)
	}
	defer netns0.Close()
	err = netlink.LinkSetNsFd(veth1, int(netns0.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	netns0.Do(func(ns.NetNS) error {
		veth1, err := netlink.LinkByName("veth1")
		if err != nil {
			t.Fatal(err)
		}
		ipnet.IP = ip1
		addr = &netlink.Addr{IPNet: ipnet}
		netlink.AddrAdd(veth1, addr)
		if err != nil {
			t.Fatal(err)
		}
		err = netlink.LinkSetUp(veth1)
		if err != nil {
			t.Fatal(err)
		}
		return nil
	})

	return veth0.Attrs().Index, veth1.Attrs().Index, fmt.Sprint("/var/run/netns/", remoteNSName), func() error {
		err := netlink.LinkDel(veth)
		err1 := netns.DeleteNamed(remoteNSName)
		if err != nil {
			return err
		}
		return err1
	}
}

func TestGetPrimaryInterfaceVethPeerIfIndex(t *testing.T) {
	testcases := []struct {
		desc          string
		interfaceName string
		wantErr       string
	}{
		{
			desc:          "get default network interface",
			interfaceName: "veth1",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			var err error
			hostIdx, nsIdx, testNSPath, deleteNSFunc := setupVethInRemoteNS(t)
			defer func() {
				if err := deleteNSFunc(); err != nil {
					t.Fatalf("deleting test network namespace failed %v", err)
				}
			}()

			testNS, err := ns.GetNS(testNSPath)
			if err != nil {
				t.Fatalf("failed to open test network namespace: %v", err)
			}
			defer testNS.Close()

			// Run the test in the root ns.
			defaultNetInPodIfIndex, vethPeer, gotErr := getPrimaryInterfaceVethPeerIfIndex("myPODID", hostIdx, testNS.Path())
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("SetupNetworkRoutes() return error %v but want nil", gotErr)
				}
				if gotErr.Error() != tc.wantErr {
					t.Fatalf("SetupNetworkRoutes() return error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}
			if vethPeer != tc.interfaceName {
				t.Fatalf("expected %v interface name but got %v", tc.interfaceName, vethPeer)
			}
			if defaultNetInPodIfIndex != nsIdx {
				t.Fatalf("expected %v interface index but got %v", nsIdx, defaultNetInPodIfIndex)
			}
		})
	}
}

func v4Route(ip, gw string, mask, mtu int, scope netlink.Scope) netlink.Route {
	route := netlink.Route{
		LinkIndex: 3,
		Scope:     scope,
		Dst: &net.IPNet{
			IP:   net.ParseIP(ip).To4(),
			Mask: net.CIDRMask(mask, 32),
		},
		Protocol: netlink.RouteProtocol(unix.RTPROT_BOOT),
		Family:   netlink.FAMILY_V4,
		Table:    unix.RT_TABLE_MAIN,
		Type:     unix.RTN_UNICAST,
		MTU:      mtu,
	}
	if gw != "" {
		route.Gw = net.ParseIP(gw)
	}
	return route
}

func v4DefaultRoute(gw string) netlink.Route {
	dr := v4Route("", gw, 0, 0, netlink.SCOPE_UNIVERSE)
	dr.Dst = nil
	return dr
}

func installRoutes(testNS ns.NetNS, routes []netlink.Route, lIdx int) error {
	return testNS.Do(func(ns.NetNS) error {
		// clear exiting
		vethPeer, err := netlink.LinkByIndex(lIdx)
		if err != nil {
			return err
		}
		delR, err := netlink.RouteList(vethPeer, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		for _, rt := range delR {
			err = netlink.RouteDel(&rt)
			if err != nil {
				return err
			}
		}

		for _, rt := range routes {
			rt.LinkIndex = lIdx
			if rt.Gw == nil {
				rt.Scope = netlink.SCOPE_LINK
			}
			if err := netlink.RouteAdd(&rt); err != nil {
				return fmt.Errorf("failed to add route '%s via dev %d': %v",
					rt.Dst.String(), rt.LinkIndex, err)
			}
		}
		return nil
	})
}

func TestGetDefaultNetworkGW(t *testing.T) {
	testcases := []struct {
		desc      string
		setRoutes []netlink.Route
		wantGW    string
		wantErr   string
	}{
		{
			desc:   "gke standard routes",
			wantGW: "192.168.1.1",
			setRoutes: []netlink.Route{
				v4Route("192.168.1.1", "", 32, 0, netlink.SCOPE_LINK),
				v4DefaultRoute("192.168.1.1"),
				v4Route("192.168.1.0", "192.168.1.1", 24, 0, netlink.SCOPE_UNIVERSE),
			},
		},
		{
			desc:   "anthos standard routes",
			wantGW: "192.168.1.253",
			setRoutes: []netlink.Route{
				v4Route("192.168.1.253", "", 32, 0, netlink.SCOPE_LINK),
				v4DefaultRoute("192.168.1.253"),
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.desc, func(t *testing.T) {
			var err error
			_, nsIdx, testNSPath, deleteNSFunc := setupVethInRemoteNS(t)
			defer func() {
				if err := deleteNSFunc(); err != nil {
					t.Fatalf("deleting test network namespace failed %v", err)
				}
			}()

			testNS, err := ns.GetNS(testNSPath)
			if err != nil {
				t.Fatalf("failed to open test network namespace: %v", err)
			}
			defer testNS.Close()
			err = installRoutes(testNS, tc.setRoutes, nsIdx)
			if err != nil {
				t.Fatalf("failed to install routes: %v", err)
			}

			// Run the test in the root ns.
			gotGW, gotErr := getDefaultNetworkGW(nsIdx, testNS.Path())
			if gotErr != nil {
				if tc.wantErr == "" {
					t.Fatalf("SetupNetworkRoutes() return error %v but want nil", gotErr)
				}
				if gotErr.Error() != tc.wantErr {
					t.Fatalf("SetupNetworkRoutes() return error %v but want %v", gotErr, tc.wantErr)
				}
				return
			}
			if gotGW != tc.wantGW {
				t.Fatalf("expected '%v' gateway, but got '%v'", tc.wantGW, gotGW)
			}
		})
	}
}
