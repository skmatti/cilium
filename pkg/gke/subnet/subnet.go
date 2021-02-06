// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package subnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// log is the subnet package logger object.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "subnetAnnotations")
)

// These are the subnet annotation keys that will be used to add subnets to the
// K8s node.
const (
	// IPv4SubnetAnnotationKey is an annotation on the Node for the NodeInternal
	// IPv4 subnet.
	IPv4SubnetAnnotationKey = "networking.gke.io/ipv4-subnet"
	// IPv6SubnetAnnotationKey is an annotation on the Node for the NodeInternal
	// IPv6 subnet.
	IPv6SubnetAnnotationKey = "networking.gke.io/ipv6-subnet"
)

// These are the Viper config map keys for the subnet annotation feature.
const (
	// ConfigAnnotateK8sNode is a viper config map key for a bool that enables
	// annotating a kubernetes node while bootstrapping the daemon. Set this in
	// kube-system:configmaps/cilium-config.
	ConfigAnnotateK8sNodeSubnet = "annotate-k8s-node-subnet"
)

// These are the logrus.Fields keys used for logging.
const (
	fieldK8sEnabled              = "k8sEnabled"
	fieldSubnetAnnotationEnabled = "subnetAnnotationEnabled"
	fieldNodeIPv4                = "nodeIPv4"
	fieldNodeIPv6                = "nodeIPv6"
	fieldPatchBytes              = "patchBytes"
)

func init() {
	viper.SetDefault(ConfigAnnotateK8sNodeSubnet, false)
}

// AnnotateNodeSubnets uses a controller to discover the IPv4 and IPv6 subnets
// associated with the node and sends a patch to K8s to update the annotations
// accordingly. It will be a no-op when K8s or the annotation config is
// disabled or both IPv4 and IPv6 are nil.
func AnnotateNodeSubnets(ctx context.Context, client kubernetes.Interface, nodeName string, nodeIPv4, nodeIPv6 net.IP) {
	enabled := viper.GetBool(ConfigAnnotateK8sNodeSubnet)
	log := log.WithFields(logrus.Fields{
		logfields.NodeName:           nodeName,
		fieldK8sEnabled:              k8s.IsEnabled(),
		fieldSubnetAnnotationEnabled: enabled,
		fieldNodeIPv4:                nodeIPv4,
		fieldNodeIPv6:                nodeIPv6,
	})
	if !k8s.IsEnabled() || !enabled {
		log.Info("Annotate K8s node subnets is disabled.")
		return
	}
	if nodeIPv4 == nil && nodeIPv6 == nil {
		log.Error(fmt.Errorf("both IPv4 and IPv6 are nil"), "Could not annotate K8s node subnets.")
		return
	}

	controller.NewManager().UpdateController("annotate-k8s-node-subnets",
		controller.ControllerParams{
			// We will not worry about running this repeatedly because if the
			// IPs change, K8s would need to be restarted anyway.
			DoFunc: func(ctx context.Context) error {
				return annotateNodeSubnets(ctx, client, nodeName, nodeIPv4, nodeIPv6)
			},
		})
}

// annotateNodeSubnets discovers the IPv4 and IPv6 subnets associated with the
// node and sends a patch to K8s to update the annotations accordingly.
func annotateNodeSubnets(ctx context.Context, client kubernetes.Interface, nodeName string, nodeIPv4, nodeIPv6 net.IP) error {
	log := log.WithFields(logrus.Fields{
		logfields.NodeName: nodeName,
		fieldNodeIPv4:      nodeIPv4,
		fieldNodeIPv6:      nodeIPv6,
	})
	log.Info("Annotating k8s node subnets")
	ipv4Subnet, err := subnetFor(nodeIPv4)
	if err != nil {
		log.WithError(err).Warn("Unable to find subnet matching nodeIPv4")
		// We do not exit because we want to apply the other annotation if it is
		// valid.
	}
	log = log.WithFields(logrus.Fields{
		fieldNodeIPv4: ipv4Subnet,
	})
	ipv6Subnet, err := subnetFor(nodeIPv6)
	if err != nil {
		log.WithError(err).Warn("Unable to find subnet matching nodeIPv6")
		// We do not exit because we want to apply the other annotation if it is
		// valid.
	}
	log = log.WithFields(logrus.Fields{
		fieldNodeIPv6: ipv6Subnet,
	})
	if ipv4Subnet == nil && ipv6Subnet == nil {
		err := fmt.Errorf("No subnets found")
		log.WithError(err).Warn("Unable to determine subnets for annotation")
		return err
	}
	patch, err := patchForSubnetAnnotations(ipv4Subnet, ipv6Subnet)
	if err != nil {
		log.WithError(err).Warn("Unable to produce patch for subnet annotations")
		return err
	}
	if _, err = client.CoreV1().Nodes().Patch(ctx, nodeName, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			fieldPatchBytes: string(patch),
		}).Warn("Unable to apply patch for subnet annotations")
		return err
	}
	log.Info("Successfully applied subnet annotations.")
	return nil
}

// subnetFor finds the subnet on the link that is associated with the given IP
// address.
//
// For nil IP, returns nil IPNet.
//
// Errors:
// - netlink fails to return links or addresses.
// - Unable to find link with matching address.
// - Matched address is not universal scope.
func subnetFor(ip net.IP) (*net.IPNet, error) {
	if ip == nil {
		return nil, nil
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if ip.Equal(addr.IP) {
				if addr.Scope != unix.RT_SCOPE_UNIVERSE {
					return nil, fmt.Errorf("found address for IP but it is not universal scope: Scope: %s", rtScopeString(addr.Scope))
				}
				return addr.IPNet, nil
			}
		}
	}
	return nil, fmt.Errorf("failed to find link with IP")
}

func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

func isIPv6(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}

// patchForSubnetAnnotations provides the json patch for subnet annotations.
//
// Errors:
// - Either subnet is not the correct family.
// - json.Marshal() fails.
func patchForSubnetAnnotations(ipv4Subnet, ipv6Subnet *net.IPNet) ([]byte, error) {
	if ipv4Subnet != nil && !isIPv4(ipv4Subnet.IP) {
		return nil, fmt.Errorf("ipv4 subnet is incorrect family: subnet: %s", ipv4Subnet)
	}
	if ipv6Subnet != nil && !isIPv6(ipv6Subnet.IP) {
		return nil, fmt.Errorf("ipv6 subnet is incorrect family: subnet: %s", ipv6Subnet)
	}
	annotations := map[string]string{}

	netToString := func(n *net.IPNet) string {
		if n == nil {
			return ""
		}
		return n.String()
	}
	annotations[IPv4SubnetAnnotationKey] = netToString(ipv4Subnet)
	annotations[IPv6SubnetAnnotationKey] = netToString(ipv6Subnet)

	raw, err := json.Marshal(annotations)
	if err != nil {
		return nil, err
	}
	patch := []byte(fmt.Sprintf(`{"metadata":{"annotations":%s}}`, raw))
	return patch, nil
}

func rtScopeString(scope int) string {
	switch scope {
	case unix.RT_SCOPE_UNIVERSE:
		return "RT_SCOPE_UNIVERSE"
	case unix.RT_SCOPE_SITE:
		return "RT_SCOPE_SITE"
	case unix.RT_SCOPE_LINK:
		return "RT_SCOPE_LINK"
	case unix.RT_SCOPE_HOST:
		return "RT_SCOPE_HOST"
	case unix.RT_SCOPE_NOWHERE:
		return "RT_SCOPE_NOWHERE"
	default:
		return "unknown RT_SCOPE value"
	}
}
