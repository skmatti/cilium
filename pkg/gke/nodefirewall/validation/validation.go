/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package validation

import (
	"fmt"
	"net"

	"gke-internal/gke-node-firewall/pkg/apis/nodenetworkpolicy/v1alpha1"

	"github.com/cilium/cilium/pkg/gke/nodefirewall/logging"
	"github.com/cilium/cilium/pkg/gke/nodefirewall/utils"
)

var (
	validPortProtocols = map[string]bool{
		string(v1alpha1.ProtocolTCP): true,
		string(v1alpha1.ProtocolUDP): true,
	}
)

// Validate verifies that node network policy is specified correctly.
// TypeMeta and ObjectMeta are not validated.
func Validate(policy *v1alpha1.NodeNetworkPolicy) error {
	logging.NodeFWLogger.Debugf("Validating policy %s", utils.PrettyPrint(policy))
	// nil ingress slice is a valid spec and denies all ingress traffic.
	if policy.Spec.Ingress == nil {
		logging.NodeFWLogger.Debug("nil Ingress spec, policy denies all ingress traffic")
		return nil
	}
	// Empty ingress slice is a valid spec and allows all ingress traffic.
	if len(policy.Spec.Ingress) == 0 {
		logging.NodeFWLogger.Debug("Empty Ingress spec, policy allows all ingress traffic")
		return nil
	}

	var errs []error
	for _, rule := range policy.Spec.Ingress {
		if err := validateIngressRule(rule); err != nil {
			errs = append(errs, err)
		}
	}
	if errs != nil {
		return fmt.Errorf("errors validating ingress rules: %v", utils.JoinErrs(errs))
	}
	logging.NodeFWLogger.Debugf("Policy %s valid", policy.Name)
	return nil
}

func validateIngressRule(rule v1alpha1.NodeNetworkPolicyIngressRule) error {
	ruleString := utils.PrettyPrint(rule)
	logging.NodeFWLogger.Debugf("Validating policy ingress rule %s", ruleString)
	if rule.Ports == nil && rule.From == nil {
		logging.NodeFWLogger.Debug("nil From and Ports, allows all incoming traffic")
		return nil
	}
	if len(rule.Ports) == 0 && len(rule.From) == 0 {
		logging.NodeFWLogger.Debug("Empty From and Ports, allows all incoming traffic")
		return nil
	}
	if len(rule.From) == 0 {
		logging.NodeFWLogger.Debug("Empty From, allows incoming traffic from all source IPs")
	}
	if len(rule.Ports) == 0 {
		logging.NodeFWLogger.Debug("Empty Ports, allows incoming traffic on all TCP ports")
	}

	var portErrs, peerErrs []error
	for _, port := range rule.Ports {
		if err := validatePort(port); err != nil {
			portErrs = append(portErrs, err)
		}
	}

	for _, peer := range rule.From {
		if err := validatePeer(peer); err != nil {
			peerErrs = append(peerErrs, err)
		}
	}

	if portErrs != nil || peerErrs != nil {
		if portErrs != nil && peerErrs != nil {
			return fmt.Errorf("invalid ingress ports: %v, invalid ingress peers: %v",
				utils.JoinErrs(portErrs), utils.JoinErrs(peerErrs))
		}
		if portErrs != nil {
			return fmt.Errorf("invalid ingress ports: %v", utils.JoinErrs(portErrs))
		}
		return fmt.Errorf("invalid ingress peers: %v", utils.JoinErrs(peerErrs))
	}
	logging.NodeFWLogger.Debugf("Policy ingress rule %s valid", ruleString)
	return nil
}

func validatePort(port v1alpha1.NodeNetworkPolicyPort) error {
	portString := utils.PrettyPrint(port)
	logging.NodeFWLogger.Debugf("Validating port %s", portString)

	// nil portProtocol is valid, traffic is not restricted based on protocol or port.
	if port.Protocol == nil && port.Port == nil {
		logging.NodeFWLogger.Debugf("nil policy port %s, allows all incoming traffic", portString)
		return nil
	}

	// nil port is invalid as cilium does not support allowing all ports for
	// a specific protocol.
	if port.Port == nil {
		return fmt.Errorf("port must be specified")
	}

	// nil Protocol is valid, allows TCP traffic on the specified port.
	if port.Protocol == nil {
		logging.NodeFWLogger.Debugf("nil protocol in policy port %s, allows incoming TCP traffic on port %q", portString, *port.Port)
	} else if !validPortProtocols[string(*port.Protocol)] {
		return fmt.Errorf("invalid port protocol %q", *port.Protocol)
	}

	if *port.Port < 0 || *port.Port > 65535 {
		return fmt.Errorf("invalid port value %q", *port.Port)
	}

	logging.NodeFWLogger.Debugf("port %s valid", portString)
	return nil
}

func validatePeer(peer v1alpha1.NodeNetworkPolicyPeer) error {
	peerString := utils.PrettyPrint(peer)
	logging.NodeFWLogger.Debugf("Validating policy peer %s", peerString)
	// Empty IPBlock is valid and allows incoming traffic on all protocols and ports.
	if peer.IPBlock == nil {
		logging.NodeFWLogger.Debugf("nil ipBlock, allows ingress from all sources")
		return nil
	}

	// Validate CIDR block.
	if err := validateCIDR(peer.IPBlock.CIDR); err != nil {
		return err
	}

	// Validate Except blocks.
	var errs []error
	for _, cidr := range peer.IPBlock.Except {
		if err := validateCIDR(cidr); err != nil {
			errs = append(errs, err)
		}
	}
	if errs != nil {
		return fmt.Errorf("invalid except CIDR blocks %q: %v", peer.IPBlock.Except, utils.JoinErrs(errs))
	}
	logging.NodeFWLogger.Debugf("Policy peer %s valid", peerString)
	return nil
}

func validateCIDR(cidr string) error {
	logging.NodeFWLogger.Debugf("Validating CIDR %s", cidr)
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return fmt.Errorf("invalid CIDR %q", cidr)
	}
	logging.NodeFWLogger.Debugf("CIDR %s valid", cidr)
	return nil
}
