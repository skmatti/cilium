package controller

import (
	"net"
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/multinet"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/utils/ptr"

	networkv1 "github.com/GoogleCloudPlatform/gke-networking-api/apis/network/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	hostInfCIDR = "10.0.1.2/24"
	linkName    = "testInf"
	ifIndex     = 10
)

var (
	zero = net.IPNet{
		IP:   net.IPv4zero,
		Mask: net.CIDRMask(0, 8*net.IPv4len),
	}
	_, d2, _ = net.ParseCIDR("10.0.1.16/32")
	addr     = &netlink.Addr{IPNet: cidr.MustParseCIDR(hostInfCIDR).IPNet}
	gw1      = net.ParseIP("10.0.0.255")
	gw2      = net.ParseIP("10.0.1.253")
)

func TestHostDevRoutingRecords(t *testing.T) {
	testutils.PrivilegedTest(t)

	testcases := []struct {
		desc        string
		network     *networkv1.Network
		wantRecords []hostDevRoutingRecord
		wantErr     string
	}{
		{
			desc: "default network expect empty records",
			network: &networkv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: networkv1.DefaultPodNetworkName,
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L3NetworkType,
				},
			},
		},
		{
			desc: "device type network expect empty records",
			network: &networkv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: networkv1.DefaultPodNetworkName,
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.DeviceNetworkType,
				},
			},
		},
		{
			desc: "l2 type network invalid gateway expect error",
			network: &networkv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L2NetworkType,
					NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
						InterfaceName: ptr.To(linkName),
					},
					Gateway4: ptr.To("invalid"),
				},
			},
			wantErr: "invalid gateway IP for network foo",
		},
		{
			desc: "l2 network missing gateway and externalDHCP set to false expect error",
			network: &networkv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L2NetworkType,
					NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
						InterfaceName: ptr.To(linkName),
					},
				},
			},
			wantErr: "failed to determine next hop address IP for network foo",
		},

		{
			desc: "l2 network missing gateway and externalDHCP set to true expect only L2 routing records",
			network: &networkv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L2NetworkType,
					NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
						InterfaceName: ptr.To(linkName),
					},
					ExternalDHCP4: ptr.To(true),
				},
			},
			wantRecords: []hostDevRoutingRecord{
				{
					key:   *multinet.NewHostDevRoutingKey(ifIndex, cidr.MustParseCIDR(hostInfCIDR).IPNet),
					entry: *multinet.NewHostDevRoutingEntry(net.IPv4zero),
				},
			},
		},
		{
			desc: "l2 type network expect non empty host dev routing records",
			network: &networkv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: networkv1.NetworkSpec{
					Type: networkv1.L2NetworkType,
					NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
						InterfaceName: ptr.To(linkName),
					},
					Gateway4: ptr.To("10.0.0.255"),
				},
			},
			wantRecords: []hostDevRoutingRecord{
				{
					key:   *multinet.NewHostDevRoutingKey(ifIndex, cidr.MustParseCIDR(hostInfCIDR).IPNet),
					entry: *multinet.NewHostDevRoutingEntry(net.IPv4zero),
				},
				{
					key:   *multinet.NewHostDevRoutingKey(ifIndex, &zero),
					entry: *multinet.NewHostDevRoutingEntry(gw1),
				},
			},
		},
		{
			desc: "l3 type network gateway set expect non empty host dev routing records",
			network: &networkv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: networkv1.NetworkSpec{
					Type:     networkv1.L3NetworkType,
					IPAMMode: ptr.To(networkv1.InternalMode),
					NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
						InterfaceName: ptr.To(linkName),
					},
					Gateway4: ptr.To("10.0.0.255"),
				},
			},
			wantRecords: []hostDevRoutingRecord{
				{
					key:   *multinet.NewHostDevRoutingKey(ifIndex, &zero),
					entry: *multinet.NewHostDevRoutingEntry(gw1),
				},
			},
		},
		{
			desc: "l3 type network missing gateway expect non empty host dev routing records",
			network: &networkv1.Network{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Spec: networkv1.NetworkSpec{
					IPAMMode: ptr.To(networkv1.InternalMode),
					Type:     networkv1.L3NetworkType,
					NodeInterfaceMatcher: networkv1.NodeInterfaceMatcher{
						InterfaceName: ptr.To(linkName),
					},
				},
			},
			wantRecords: []hostDevRoutingRecord{
				{
					key:   *multinet.NewHostDevRoutingKey(ifIndex, &zero),
					entry: *multinet.NewHostDevRoutingEntry(gw2),
				},
			},
		},
	}

	r := NetworkReconciler{
		Log: logging.DefaultLogger.WithField(logfields.LogSubsys, "test"),
	}
	for _, tc := range testcases {
		testFunc := func() {
			if tc.network.Spec.NodeInterfaceMatcher.InterfaceName != nil {
				defer cleanupLinks(t, *tc.network.Spec.NodeInterfaceMatcher.InterfaceName)
				l := setupParentLinkWithAttrs(t, netlink.LinkAttrs{Name: *tc.network.Spec.NodeInterfaceMatcher.InterfaceName, Index: 10})
				if err := netlink.AddrAdd(l, addr); err != nil {
					t.Fatalf("failed to add address to link: %v,", err)
				}
				// destination in same network as node via gateway
				if err := netlink.RouteAdd(&netlink.Route{
					LinkIndex: l.Attrs().Index,
					Gw:        gw2,
					Table:     unix.RT_TABLE_MAIN,
					Scope:     netlink.SCOPE_UNIVERSE,
					Dst:       d2,
				}); err != nil {
					t.Fatalf("failed to add route to link: %v,", err)
				}
			}
			gotRecords, gotErr := r.hostDevRoutingRecords(tc.network)
			if gotErr == nil && tc.wantErr != "" {
				t.Fatalf("got nil error but wanted error: %v,", tc.wantErr)
			}
			if gotErr != nil && tc.wantErr == "" {
				t.Fatalf("got error expected no error: %v,", gotErr)
			}
			if gotErr != nil && gotErr.Error() != tc.wantErr {
				t.Fatalf("got error: %v, wantErr: %v", gotErr, tc.wantErr)
			}
			if !reflect.DeepEqual(gotRecords, tc.wantRecords) {
				t.Errorf("unexpected hostDevRoutingRecords(...) for case %s, got: %v, want: %v", tc.desc, gotRecords, tc.wantRecords)
			}
		}
		t.Run(tc.desc, func(t *testing.T) { runTestInNetNS(t, testFunc) })
	}
}
