package controller

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// The special egress gateway IP we are going to use.
	// This must be a IP no one is suppose to use.
	strictEgressPolicyValidationEgressIP = netip.MustParseAddr("255.255.255.254")
	// We use 0.0.0.0/0 for destination, so `lookup_ip4_egress_gw_policy` in bpf_lxc can always
	// match based on source IP only.
	strictEgressPolicyValidationDstCIDR = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	// This must be of the same value of egressgateway.ExcludedCIDRIPv4 in pkg/egressgateway/manager.go
	// OSS Cilium already has the logic to skip egress gateway logic when it sees this gateway IP,
	// so we can leverage this IP to indicate the traffic is "allowed".
	// (We cannot import the value here directly as it will cause a circular dependency)
	strictEgressPolicyValidationGatewayIP = netip.MustParseAddr("0.0.0.1")

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "google-strict-egress-policy-validation")

	DefaultStrictEgressPolicyValidationAllowAccessLabels = []string{"networking.private.gdc.goog/infra-access=enabled"}
)

const (
	DefaultEnableStrictEgressPolicyValidation                        = false
	DefaultStrictEgressPolicyValidationReconciliationTriggerInterval = 1 * time.Second
)
