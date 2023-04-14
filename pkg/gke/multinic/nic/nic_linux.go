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
	LoopbackDevName = "lo"
)

var (
	// Possible padding with 0-4 zeros for domain
	bdfMatcher = regexp.MustCompile(`\b(0{0,4}:\d{2}:\d{2}.\d)`)
)

type NIC struct {
	Name       string
	PCIAddress *string
}

func ToPCIAddr(iface string) (string, error) {
	if iface == LoopbackDevName {
		return "", nil
	}
	// We do readlink on something like /sys/class/net/eth0
	// We get something like ../../devices/pci0000:00/0000:00:04.0/virtio1/net/eth0
	// for virtio or  ../../devices/pci0000:00/0000:00:04.0/net/eth1 for gve
	dest, err := os.Readlink(filepath.Join(pathSysClassNet, iface))
	if err != nil {
		return "", err
	}
	// Virtual devices will have something like
	// /sys/devices/virtual/net/gke001b3b37560
	if strings.Contains(dest, "devices/virtual/net") {
		return "", nil
	}
	// We get something like /sys/devices/pci0000:00/0000:00:04.0/virtio1/net/eth0
	// or for gve /sys/devices/pci0000:00/0000:00:04.0/net/eth1
	absPath, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	return bdfMatcher.FindString(absPath), nil
}

func IsVirtual(iface string) (bool, error) {
	if iface == LoopbackDevName {
		return true, nil
	}
	dest, err := os.Readlink(filepath.Join(pathSysClassNet, iface))
	if err != nil {
		return false, err
	}
	return strings.Contains(dest, "devices/virtual/net"), nil
}

func FindPCINICs() ([]*NIC, error) {
	nics := make([]*NIC, 0)

	files, err := ioutil.ReadDir(pathSysClassNet)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v: %v", pathSysClassNet, err)
	}

	for _, file := range files {
		devName := file.Name()
		pciAddr, err := ToPCIAddr(devName)
		if err != nil {
			return nil, err
		}
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
