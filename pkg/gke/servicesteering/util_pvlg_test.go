package servicesteering

import (
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
	"github.com/vishvananda/netlink"
	v1 "gke-internal.googlesource.com/anthos-networking/apis/v2/service-steering/v1"
)

func TestRemoveDevice(t *testing.T) {
	testutils.PrivilegedTest(t)

	testCases := []struct {
		name     string
		existing bool
	}{
		{
			name:     "delete existing device",
			existing: true,
		},
		{
			name:     "delete non-existent device",
			existing: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verifyDevExists(t, geneveDevName, false)
			if tc.existing {
				if err := addGeneveDev(geneveDevName, sfclog); err != nil {
					t.Fatal(err)
				}
			}
			verifyDevExists(t, geneveDevName, tc.existing)
			if err := removeDevice(geneveDevName, sfclog); err != nil {
				t.Fatal(err)
			}
			verifyDevExists(t, geneveDevName, false)
		})
	}

}

func TestAddGeneveDev(t *testing.T) {
	testutils.PrivilegedTest(t)

	testCases := []struct {
		name     string
		existing bool
	}{
		{
			name:     "add new device",
			existing: false,
		},
		{
			name:     "add existing device",
			existing: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verifyDevExists(t, geneveDevName, false)
			defer removeDevice(geneveDevName, sfclog)
			if tc.existing {
				if err := addGeneveDev(geneveDevName, sfclog); err != nil {
					t.Fatal(err)
				}
				verifyDevExists(t, geneveDevName, true)
			}
			if err := addGeneveDev(geneveDevName, sfclog); err != nil {
				t.Fatal(err)
			}
			verifyDevExists(t, geneveDevName, true)
			verifyGeneveDev(t, geneveDevName)
		})
	}

}

func verifyDevExists(t *testing.T, name string, exists bool) {
	l, err := netlink.LinkByName(name)
	if err != nil && exists {
		t.Fatalf("device %s doesn't exists", name)
	}
	if err == nil && !exists {
		t.Fatalf("device %s exists but want non-existent", name)
	}
	if err == nil {
		t.Logf("netlink: %+v", l)
	}
}

func verifyGeneveDev(t *testing.T, name string) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("device %s doesn't exists", name)
	}
	g, ok := l.(*netlink.Geneve)
	if !ok {
		t.Fatalf("device %s is not a geneve device %T", name, l)
	}
	if got, want := g.Dport, uint16(v1.SvcSteeringPort); got != want {
		t.Fatalf("Destination port wrong (got vs want): %d vs %d", got, want)
	}
	// TODO(b/332375625): Add verification of FlowBased once netlink version is bumped in cilium 1.15.
	/*if !g.FlowBased {
		t.Fatalf("FlowBased is not set on device %s", name)
	}*/
}
