package localnodeip

import (
	"net"

	"github.com/cilium/cilium/pkg/lock"
)

var (
	nodeIP net.IP
	mu     lock.RWMutex
)

// CIDRMatchesLocalNode determines whether the CIDR matches the local node IP.
func CIDRMatchesLocalNode(cidr string) bool {
	localIP := GetK8sNodeIP()
	if localIP == nil {
		return false
	}
	_, allowNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return allowNet.Contains(localIP)
}

func GetK8sNodeIP() net.IP {
	mu.RLock()
	defer mu.RUnlock()
	return nodeIP
}

func SetK8sNodeIP(ip net.IP) {
	mu.Lock()
	defer mu.Unlock()
	nodeIP = ip
}
