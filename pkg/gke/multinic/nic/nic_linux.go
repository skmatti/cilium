//go:build linux

package nic

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// sysfs is mounted by runc automatically, so this should always be readable
	pathSysClassNet = "/sys/class/net"
	loopbackDevName = "lo"
)

var (
	// Possible padding with 0-4 zeros for domain
	bdfMatcher = regexp.MustCompile(`\b(0{0,4}:\d{2}:\d{2}.\d)`)
)

type NIC struct {
	Name       string
	PCIAddress *string
}

func FindPCINICs() ([]*NIC, error) {
	nics := make([]*NIC, 0)

	files, err := ioutil.ReadDir(pathSysClassNet)
	if err != nil {
		return nil, fmt.Errorf("Failed to read %v: %v", pathSysClassNet, err)
	}

	for _, file := range files {
		devName := file.Name()
		// we ignore lo device here
		if devName == loopbackDevName {
			continue
		}

		// We do readlink on something like /sys/class/net/eth0
		// We get something like ../../devices/pci0000:00/0000:00:04.0/virtio1/net/eth0
		// for virtio or  ../../devices/pci0000:00/0000:00:04.0/net/eth1 for gve
		dest, err := os.Readlink(filepath.Join(pathSysClassNet, devName))
		if err != nil {
			return nil, err
		}

		// Virtual devices will have something like
		// /sys/devices/virtual/net/gke001b3b37560
		if strings.Contains(dest, "devices/virtual/net") {
			// Virtual devices don't have PCI address
			continue
		}

		// We get something like /sys/devices/pci0000:00/0000:00:04.0/virtio1/net/eth0
		// or for gve /sys/devices/pci0000:00/0000:00:04.0/net/eth1
		absPath, err := filepath.Abs(dest)
		if err != nil {
			return nil, err
		}

		pciAddr := bdfMatcher.FindString(absPath)
		if pciAddr == "" {
			// Ignore non-PCI NICs
			continue
		}

		nic := &NIC{
			Name:       devName,
			PCIAddress: &pciAddr,
		}
		nics = append(nics, nic)
	}
	return nics, nil
}
