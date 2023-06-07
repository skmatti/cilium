//go:build linux

package nic

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
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
	// Possible padding with 4 hex char for domain
	bdfMatcher = regexp.MustCompile(`\b([[:xdigit:]]{0,4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}.\d)`)
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
	// We get something like ../../devices/pci0000:00/0000:00:0a.0/0000:00:04.0/virtio1/net/eth0
	// for virtio or  ../../devices/pci0000:00/0000:00:0a.0/0000:00:04.0/net/eth1 for gve
	dest, err := os.Readlink(filepath.Join(pathSysClassNet, iface))
	if err != nil {
		return "", err
	}
	// Virtual devices will have something like
	// /sys/devices/virtual/net/gke001b3b37560
	if strings.Contains(dest, "devices/virtual/net") {
		return "", nil
	}

	// We get something like /sys/devices/pci0000:00/0000:00:0a.0/0000:00:04.0/virtio1/net/eth0
	// or for gve /sys/devices/pci0000:00/0000:00:0a.0/0000:00:04.0/net/eth1
	absPath, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}

	// Might have pci switches in the path, so could have multiple BDFs
	addrs := bdfMatcher.FindAllString(absPath, -1)
	if len(addrs) == 0 {
		return "", fmt.Errorf("failed find BDF in path %v", absPath)
	}
	// The BDF of the device is the last segment.
	return addrs[len(addrs)-1], nil
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

// RemoveAltnameFromInterface runs `ip link property del dev <name> altname <altname>`
func RemoveAltnameFromInterface(ifaceName string, altname string) (string, error) {
	cmd := exec.Command("ip", "link", "property", "del", "dev", ifaceName, "altname", altname)
	output, err := cmd.CombinedOutput()
	// we return output regardless of error
	return string(output[:]), err
}
