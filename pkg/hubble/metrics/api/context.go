// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/utils/strings/slices"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/labels"
)

// ContextIdentifier describes the identification method of a transmission or
// receiving context
type ContextIdentifier int

const (
	// ContextDisabled disables context identification
	ContextDisabled ContextIdentifier = iota
	// ContextIdentity uses the full set of identity labels for identification purposes
	ContextIdentity
	// ContextNamespace uses the namespace name for identification purposes
	ContextNamespace
	// ContextPod uses the pod name for identification purposes
	ContextPod
	// ContextPodShort uses a short version of the pod name. It should
	// typically map to the deployment/replicaset name
	ContextPodShort
	// ContextDNS uses the DNS name for identification purposes
	ContextDNS
	// ContextIP uses the IP address for identification purposes
	ContextIP
	// ContextReservedIdentity uses reserved labels in the identity label list for identification
	// purpose. It uses "reserved:kube-apiserver" label if it's present in the identity label list.
	// Otherwise, it uses the first label in the identity label list with "reserved:" prefix.
	ContextReservedIdentity
	// ContextWorkloadName uses the pod's workload name for identification.
	ContextWorkloadName
)

// ContextOptionsHelp is the help text for context options
const ContextOptionsHelp = `
 sourceContext             ::= identifier , { "|", identifier }
 destinationContext        ::= identifier , { "|", identifier }
 sourceEgressContext       ::= identifier , { "|", identifier }
 sourceIngressContext      ::= identifier , { "|", identifier }
 destinationEgressContext  ::= identifier , { "|", identifier }
 destinationIngressContext ::= identifier , { "|", identifier }
 identifier                ::= identity | namespace | pod | pod-short | dns | ip | reserved-identity | workload-name
`

var (
	shortPodPattern    = regexp.MustCompile("^(.+?)(-[a-z0-9]+){1,2}$")
	kubeAPIServerLabel = labels.LabelKubeAPIServer.String()
)

// String return the context identifier as string
func (c ContextIdentifier) String() string {
	switch c {
	case ContextDisabled:
		return "disabled"
	case ContextIdentity:
		return "identity"
	case ContextNamespace:
		return "namespace"
	case ContextPod:
		return "pod"
	case ContextPodShort:
		return "pod-short"
	case ContextDNS:
		return "dns"
	case ContextIP:
		return "ip"
	case ContextReservedIdentity:
		return "reserved-identity"
	case ContextWorkloadName:
		return "workload-name"
	}
	return fmt.Sprintf("%d", c)
}

type ContextIdentifierList []ContextIdentifier

func (cs ContextIdentifierList) String() string {
	s := make([]string, 0, len(cs))
	for _, c := range cs {
		s = append(s, c.String())
	}
	return strings.Join(s, "|")
}

// ContextOptions is the set of options to define whether and how to include
// sending and/or receiving context information
type ContextOptions struct {
	// Destination is the destination context to include in metrics for both egress and ingress traffic
	Destination ContextIdentifierList
	// Destination is the destination context to include in metrics for egress traffic (overrides Destination)
	DestinationEgress ContextIdentifierList
	// Destination is the destination context to include in metrics for ingress traffic (overrides Destination)
	DestinationIngress ContextIdentifierList

	allDestinationCtx ContextIdentifierList

	// Source is the source context to include in metrics for both egress and ingress traffic
	Source ContextIdentifierList
	// Source is the source context to include in metrics for egress traffic (overrides Source)
	SourceEgress ContextIdentifierList
	// Source is the source context to include in metrics for ingress traffic (overrides Source)
	SourceIngress ContextIdentifierList

	allSourceCtx ContextIdentifierList
}

func parseContextIdentifier(s string) (ContextIdentifier, error) {
	switch strings.ToLower(s) {
	case "identity":
		return ContextIdentity, nil
	case "namespace":
		return ContextNamespace, nil
	case "pod":
		return ContextPod, nil
	case "pod-short":
		return ContextPodShort, nil
	case "dns":
		return ContextDNS, nil
	case "ip":
		return ContextIP, nil
	case "reserved-identity":
		return ContextReservedIdentity, nil
	case "workload-name":
		return ContextWorkloadName, nil
	default:
		return ContextDisabled, fmt.Errorf("unknown context '%s'", s)
	}
}

func parseContext(s string) (cs ContextIdentifierList, err error) {
	for _, v := range strings.Split(s, "|") {
		c, err := parseContextIdentifier(v)
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
	}

	return cs, nil
}

// ParseContextOptions parses a set of options and extracts the context
// relevant options
func ParseContextOptions(options Options) (*ContextOptions, error) {
	o := &ContextOptions{}
	var err error
	for key, value := range options {
		switch strings.ToLower(key) {
		case "destinationcontext":
			o.Destination, err = parseContext(value)
			o.allDestinationCtx = append(o.allDestinationCtx, o.Destination...)
			if err != nil {
				return nil, err
			}
		case "destinationegresscontext":
			o.DestinationEgress, err = parseContext(value)
			o.allDestinationCtx = append(o.allDestinationCtx, o.DestinationEgress...)
			if err != nil {
				return nil, err
			}
		case "destinationingresscontext":
			o.DestinationIngress, err = parseContext(value)
			o.allDestinationCtx = append(o.allDestinationCtx, o.DestinationIngress...)
			if err != nil {
				return nil, err
			}
		case "sourcecontext":
			o.Source, err = parseContext(value)
			o.allSourceCtx = append(o.allSourceCtx, o.Source...)
			if err != nil {
				return nil, err
			}
		case "sourceegresscontext":
			o.SourceEgress, err = parseContext(value)
			o.allSourceCtx = append(o.allSourceCtx, o.SourceEgress...)
			if err != nil {
				return nil, err
			}
		case "sourceingresscontext":
			o.SourceIngress, err = parseContext(value)
			o.allSourceCtx = append(o.allSourceCtx, o.SourceIngress...)
			if err != nil {
				return nil, err
			}
		}
	}

	return o, nil
}

func sourceNamespaceContext(flow *pb.Flow) (context string) {
	if flow.GetSource() != nil {
		context = flow.GetSource().Namespace
	}
	return
}

func sourceIdentityContext(flow *pb.Flow) (context string) {
	if flow.GetSource() != nil {
		context = strings.Join(flow.GetSource().Labels, ",")
	}
	return
}

func sourceReservedIdentityContext(flow *pb.Flow) (context string) {
	if flow.GetSource() != nil {
		context = handleReservedIdentityLabels(flow.GetSource().Labels)
	}
	return
}

func sourcePodContext(flow *pb.Flow) (context string) {
	if flow.GetSource() != nil {
		context = flow.GetSource().PodName
		if flow.GetSource().Namespace != "" {
			context = flow.GetSource().Namespace + "/" + context
		}
	}
	return
}

func shortenPodName(name string) string {
	return shortPodPattern.ReplaceAllString(name, "${1}")
}

func sourcePodShortContext(flow *pb.Flow) (context string) {
	if flow.GetSource() != nil {
		context = shortenPodName(flow.GetSource().PodName)
		if flow.GetSource().Namespace != "" {
			context = flow.GetSource().Namespace + "/" + context
		}
	}
	return
}

func sourceDNSContext(flow *pb.Flow) (context string) {
	if flow.GetSourceNames() != nil {
		context = strings.Join(flow.GetSourceNames(), ",")
	}
	return
}

func sourceIPContext(flow *pb.Flow) (context string) {
	if flow.GetIP() != nil {
		context = flow.GetIP().GetSource()
	}
	return
}

func destinationNamespaceContext(flow *pb.Flow) (context string) {
	if flow.GetDestination() != nil {
		context = flow.GetDestination().Namespace
	}
	return
}

func handleReservedIdentityLabels(lbls []string) string {
	// if reserved:kube-apiserver label is present, return it (instead of reserved:world, etc..)
	if slices.Contains(lbls, kubeAPIServerLabel) {
		return kubeAPIServerLabel
	}
	// else return the first reserved label.
	for _, label := range lbls {
		if strings.HasPrefix(label, labels.LabelSourceReserved+":") {
			return label
		}
	}
	return ""
}

func destinationIdentityContext(flow *pb.Flow) (context string) {
	if flow.GetDestination() != nil {
		context = strings.Join(flow.GetDestination().Labels, ",")
	}
	return
}

func destinationReservedIdentityContext(flow *pb.Flow) (context string) {
	if flow.GetDestination() != nil {
		context = handleReservedIdentityLabels(flow.GetDestination().Labels)
	}
	return
}

func destinationPodContext(flow *pb.Flow) (context string) {
	if flow.GetDestination() != nil {
		context = flow.GetDestination().PodName
		if flow.GetDestination().Namespace != "" {
			context = flow.GetDestination().Namespace + "/" + context
		}
	}
	return
}

func destinationPodShortContext(flow *pb.Flow) (context string) {
	if flow.GetDestination() != nil {
		context = shortenPodName(flow.GetDestination().PodName)
		if flow.GetDestination().Namespace != "" {
			context = flow.GetDestination().Namespace + "/" + context
		}
	}
	return
}

func destinationDNSContext(flow *pb.Flow) (context string) {
	if flow.GetDestinationNames() != nil {
		context = strings.Join(flow.GetDestinationNames(), ",")
	}
	return
}

func destinationIPContext(flow *pb.Flow) (context string) {
	if flow.GetIP() != nil {
		context = flow.GetIP().GetDestination()
	}
	return
}

// GetLabelValues returns the values of the context relevant labels according
// to the configured options. The order of the values is the same as the order
// of the label names returned by GetLabelNames()
func (o *ContextOptions) GetLabelValues(flow *pb.Flow) (labels []string) {
	var sourceContextIdentifiers = o.Source
	if o.SourceIngress != nil && flow.GetTrafficDirection() == pb.TrafficDirection_INGRESS {
		sourceContextIdentifiers = o.SourceIngress
	} else if o.SourceEgress != nil && flow.GetTrafficDirection() == pb.TrafficDirection_EGRESS {
		sourceContextIdentifiers = o.SourceEgress
	}
	if len(sourceContextIdentifiers) != 0 {
		var context string
		for _, source := range sourceContextIdentifiers {
			switch source {
			case ContextNamespace:
				context = sourceNamespaceContext(flow)
			case ContextIdentity:
				context = sourceIdentityContext(flow)
			case ContextPod:
				context = sourcePodContext(flow)
			case ContextPodShort:
				context = sourcePodShortContext(flow)
			case ContextDNS:
				context = sourceDNSContext(flow)
			case ContextIP:
				context = sourceIPContext(flow)
			case ContextReservedIdentity:
				context = sourceReservedIdentityContext(flow)
			case ContextWorkloadName:
				if id := flow.GetSource(); id != nil {
					if workloads := id.GetWorkloads(); len(workloads) != 0 {
						context = workloads[0].Name
					}
				}
			}
			// always use first non-empty context
			if context != "" {
				break
			}
		}
		labels = append(labels, context)
	}

	var destinationContextIdentifiers = o.Destination
	if o.DestinationIngress != nil && flow.GetTrafficDirection() == pb.TrafficDirection_INGRESS {
		destinationContextIdentifiers = o.DestinationIngress
	} else if o.DestinationEgress != nil && flow.GetTrafficDirection() == pb.TrafficDirection_EGRESS {
		destinationContextIdentifiers = o.DestinationEgress
	}
	if len(destinationContextIdentifiers) != 0 {
		var context string
		for _, destination := range destinationContextIdentifiers {
			switch destination {
			case ContextNamespace:
				context = destinationNamespaceContext(flow)
			case ContextIdentity:
				context = destinationIdentityContext(flow)
			case ContextPod:
				context = destinationPodContext(flow)
			case ContextPodShort:
				context = destinationPodShortContext(flow)
			case ContextDNS:
				context = destinationDNSContext(flow)
			case ContextIP:
				context = destinationIPContext(flow)
			case ContextReservedIdentity:
				context = destinationReservedIdentityContext(flow)
			case ContextWorkloadName:
				if id := flow.GetDestination(); id != nil {
					if workloads := id.GetWorkloads(); len(workloads) != 0 {
						context = workloads[0].Name
					}
				}
			}
			// always use first non-empty context
			if context != "" {
				break
			}
		}
		labels = append(labels, context)
	}

	return
}

// GetLabelNames returns a slice of label names required to fulfil the
// configured context description requirements
func (o *ContextOptions) GetLabelNames() (labels []string) {
	if len(o.Source) != 0 {
		labels = append(labels, "source")
	}

	if len(o.Destination) != 0 {
		labels = append(labels, "destination")
	}

	return
}

// Status returns the configuration status of context options suitable for use
// with Handler.Status
func (o *ContextOptions) Status() string {
	var status []string
	if len(o.Source) != 0 {
		status = append(status, "source="+o.Source.String())
	}

	if len(o.Destination) != 0 {
		status = append(status, "destination="+o.Destination.String())
	}

	sort.Strings(status)

	return strings.Join(status, ",")
}

func (o *ContextOptions) DeleteMetricsAssociatedWithPod(name string, namespace string, vec *prometheus.MetricVec) {
	for _, contextID := range o.allSourceCtx {
		if contextID == ContextPod {
			vec.DeletePartialMatch(prometheus.Labels{
				"source": namespace + "/" + name,
			})
		}
	}
	for _, contextID := range o.allDestinationCtx {
		if contextID == ContextPod {
			vec.DeletePartialMatch(prometheus.Labels{
				"destination": namespace + "/" + name,
			})
		}
	}

}
