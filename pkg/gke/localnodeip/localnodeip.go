package localnodeip

import (
	"net"
	"os"

	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "localnodeip")
	// nodeIP is the node's k8s Node object .status.ip value.
	nodeIP net.IP
)

func init() {

	if !components.IsCiliumAgent() {
		return
	}

	// "MTU_DEVICE_IP" is the node IP address per the node's status field.
	// This value must never change.
	ip, ok := os.LookupEnv("MTU_DEVICE_IP")
	if !ok || ip == "" {
		log.Error("MTU_DEVICE_IP must be set")
	}
	setDeviceIP(ip)
}

func setDeviceIP(ip string) {
	if nodeIP = net.ParseIP(ip); nodeIP == nil {
		log.Errorf("Failed to parse ip: %v", ip)
	}
}

// CIDRMatchesLocalNode determines whether the CIDR matches the local node IP.
func CIDRMatchesLocalNode(cidr string) bool {
	if !components.IsCiliumAgent() {
		return false
	}
	// When PolicyCIDRMatchesNodes is enabled, we disable this check because
	// the policy is intended to match based on Node IPs, not local IPs.
	if option.Config.PolicyCIDRMatchesNodes() {
		return false
	}
	if nodeIP == nil {
		log.Error("Node IP not set. Node CIDR based network policy cannot be enforced.")
		return false
	}
	_, allowNet, err := net.ParseCIDR(cidr)
	if err != nil {
		log.WithError(err).Error("Node CIDR based network policy cannot be enforced.")
		return false
	}
	return allowNet.Contains(nodeIP)
}
