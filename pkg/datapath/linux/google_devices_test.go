// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linux

import (
	"context"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/gke/features"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	. "gopkg.in/check.v1"
)

// TODO(b/279040119) Filter out user-provided prefixes until we have a better solution
// for dynamic device detection (b/263520677)
func (s *DevicesSuite) TestExcludeDevicesWithUserProvidedPrefixes(c *C) {
	s.withFreshNetNS(c, func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		timeout := time.After(time.Second)

		option.Config.DevicePrefixesToExclude = []string{"exclude"}
		option.Config.SetDevices([]string{"dummy+"})
		dm, err := NewDeviceManager()
		c.Assert(err, IsNil)

		// Test that we exclude the specified devices on startup
		c.Assert(createDummy("dummy0", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("dummy1", "192.90.3.4/24", false), IsNil)
		c.Assert(createDummy("exclude123", "100.5.100.0/20", false), IsNil)

		// Detect the devices
		devices, err := dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"dummy0", "dummy1"})

		// Add two new devices before listening
		c.Assert(createDummy("dummy2", "192.100.1.2/24", false), IsNil)
		c.Assert(createDummy("exclude45", "100.5.120.0/20", false), IsNil)

		// Now start listening to device changes. We expect all the dummy
		// devices to be present, and none of the exclude devices
		devicesChan, err := dm.Listen(ctx)
		c.Assert(err, IsNil)

		passed := false
		for !passed {
			select {
			case <-timeout:
				c.Fatal("Test timed out")
			case devices := <-devicesChan:
				passed, _ = checker.DeepEqual(devices, []string{"dummy0", "dummy1", "dummy2"})
			}
		}
	})
}

func (s *DevicesSuite) TestDevicesWithK8sInterfaceOnly(c *C) {
	s.withFreshNetNS(c, func() {
		dm, err := NewDeviceManager()
		c.Assert(err, IsNil)

		currentValue := features.GlobalConfig.K8sInterfaceOnly
		defer func() {
			features.GlobalConfig.K8sInterfaceOnly = currentValue
			option.Config.SetDevices([]string{})
		}()
		features.GlobalConfig.K8sInterfaceOnly = true
		option.Config.EnableHostFirewall = true
		node.SetIPv4(net.ParseIP("192.168.2.2"))

		// Test that we exclude the specified devices on startup
		c.Assert(createDummy("ifName0", "192.168.2.2/24", false), IsNil)
		c.Assert(createDummy("ifName1", "192.90.3.4/24", false), IsNil)
		c.Assert(createDummy("exclude123", "100.5.100.0/20", false), IsNil)

		// Detect the devices
		devices, err := dm.Detect(true)
		c.Assert(err, IsNil)
		c.Assert(devices, checker.DeepEquals, []string{"ifName0"})
	})
}
