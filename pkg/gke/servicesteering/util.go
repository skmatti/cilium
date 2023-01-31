package servicesteering

import (
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/maps/sfc"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/u8proto"
	v1 "gke-internal.googlesource.com/anthos-networking/apis/v2/service-steering/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var exists = struct{}{}

type portSelector struct {
	portNumber uint16
	proto      u8proto.U8proto
}

type identityNotReady struct{}

func (m identityNotReady) Error() string {
	return "identity is not ready"
}

func isIdentityNotReady(err error) bool {
	_, ok := err.(identityNotReady)
	return ok
}

func CRDsExist(rest meta.RESTMapper) (bool, error) {
	version := v1.GroupVersion.Version
	if _, err := rest.RESTMapping(v1.Kind(v1.KindServiceFunctionChain), version); err != nil {
		return false, ignoreNoMatchError(err)
	}
	if _, err := rest.RESTMapping(v1.Kind(v1.KindTrafficSelector), version); err != nil {
		return false, ignoreNoMatchError(err)
	}
	return true, nil
}

func mapTStoSFC(obj client.Object) []ctrl.Request {
	ts := obj.(*v1.TrafficSelector)
	sfcName := ts.Spec.ServiceFunctionChain
	return []ctrl.Request{{NamespacedName: types.NamespacedName{Name: sfcName}}}
}

func isValidSFC(obj client.Object) bool {
	sfc, ok := obj.(*v1.ServiceFunctionChain)
	if !ok {
		return false
	}
	return sfc.Status.ServicePathId != nil
}

func isValidSvc(obj client.Object) bool {
	svc, ok := obj.(*corev1.Service)
	if !ok {
		return false
	}
	clusterIP := svc.Spec.ClusterIP
	return clusterIP != "" && clusterIP != corev1.ClusterIPNone
}

func ignoreNoMatchError(err error) error {
	if meta.IsNoMatchError(err) {
		return nil
	}
	return err
}

func newExtractedSelector(ts *v1.TrafficSelector) (*extractedSelector, error) {
	selector := extractedSelector{TrafficSelector: ts}
	if err := selector.extractCIDR(); err != nil {
		return nil, fmt.Errorf("unable to extract CIDR: %v", err)
	}
	if err := selector.extractPorts(); err != nil {
		return nil, fmt.Errorf("unable to extract ports: %v", err)
	}
	if err := selector.extractSubject(); err != nil {
		return nil, fmt.Errorf("unable to extract subject: %v", err)
	}
	return &selector, nil
}

func (ts *extractedSelector) matchesLabels(labels labels.Set) error {
	if nsMatches := ts.nsSelector.Matches(labels); !nsMatches {
		return fmt.Errorf("namespace labels do not match")
	}
	if podMatches := ts.podSelector.Matches(labels); !podMatches {
		return fmt.Errorf("pod labels do not match")
	}
	return nil
}

func (ts *extractedSelector) extractCIDR() error {
	var peer *v1.TrafficSelectorPeer
	if ts.Spec.Egress != nil {
		peer = ts.Spec.Egress.To
	} else if ts.Spec.Ingress != nil {
		peer = ts.Spec.Ingress.From
	} else {
		return fmt.Errorf("missing ingress/egress")
	}

	var cidr net.IPNet
	if peer != nil && peer.IPBlock != nil {
		_, parsedCIDR, err := net.ParseCIDR(peer.IPBlock.CIDR)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %v", peer.IPBlock.CIDR, err)
		}
		cidr = *parsedCIDR
	} else {
		cidr = sfc.AllIPv4
	}

	ts.cidr = cidr
	return nil
}

func (ts *extractedSelector) extractPorts() error {
	var ports []v1.TrafficSelectorPort

	if ts.Spec.Egress != nil {
		ports = ts.Spec.Egress.Ports
	} else if ts.Spec.Ingress != nil {
		ports = ts.Spec.Ingress.Ports
	} else {
		return fmt.Errorf("missing ingress/egress")
	}

	if ports == nil || len(ports) == 0 {
		// Empty ports is equivalent to all ports for TCP and UDP
		return fmt.Errorf("empty ports is not supported")
	}
	parsedPorts := make(map[portSelector]struct{})
	for _, p := range ports {
		var portNumber uint16
		var protoStr string
		if p.AllPorts != nil {
			portNumber = 0 // 0 indicates all ports
			protoStr = string(p.AllPorts.Protocol)
		} else if p.PortNumber != nil {
			portNumber = uint16(p.PortNumber.Port)
			protoStr = string(p.PortNumber.Protocol)
		} else {
			return fmt.Errorf("unsupported port selector")
		}

		proto, err := u8proto.ParseProtocol(protoStr)
		if err != nil || !sfc.SupportedProtocol(proto) {
			return fmt.Errorf("unsupported protocol %s", protoStr)
		}
		parsedPorts[portSelector{portNumber, proto}] = exists
	}

	ts.portSelectors = parsedPorts
	return nil
}

func (ts *extractedSelector) extractSubject() error {
	nsLabelSelector := ts.Spec.Subject.Pods.NamespaceSelector
	prefixedNsLabelSelector := metav1.LabelSelector{
		MatchLabels:      make(map[string]string),
		MatchExpressions: make([]metav1.LabelSelectorRequirement, 0, len(nsLabelSelector.MatchExpressions)),
	}

	// Endpoint's namespace labels have a prefix: "io.cilium.k8s.namespace.labels",
	// so add the prefix to the selectors as well
	for k, v := range nsLabelSelector.MatchLabels {
		prefixedNsLabelSelector.MatchLabels[policy.JoinPath(ciliumio.PodNamespaceMetaLabels, k)] = v
	}
	for _, lsr := range nsLabelSelector.MatchExpressions {
		lsr.Key = policy.JoinPath(ciliumio.PodNamespaceMetaLabels, lsr.Key)
		prefixedNsLabelSelector.MatchExpressions = append(prefixedNsLabelSelector.MatchExpressions, lsr)
	}
	nsSelector, err := metav1.LabelSelectorAsSelector(&prefixedNsLabelSelector)
	if err != nil {
		return fmt.Errorf("invalid namespace selector: %v", err)
	}
	podSelector, err := metav1.LabelSelectorAsSelector(&ts.Spec.Subject.Pods.PodSelector)
	if err != nil {
		return fmt.Errorf("invalid pod selector: %v", err)
	}

	ts.nsSelector = nsSelector
	ts.podSelector = podSelector
	return nil
}

// Returns existing SFC path map entries
func existingPaths() (map[sfc.PathKey]sfc.PathEntry, error) {
	dump := make(map[sfc.PathKey]sfc.PathEntry)
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*sfc.PathKey).DeepCopy()
		value := v.(*sfc.PathEntry).DeepCopy()
		dump[*key] = *value
	}
	stats := bpf.NewDumpStats(sfc.PathMap)
	err := sfc.PathMap.DumpReliablyWithCallback(cb, stats)
	if err != nil {
		return nil, err
	}
	return dump, nil
}

// Returns existing CIDR map entries
func existingCIDRs() (map[sfc.CIDRKey]sfc.CIDREntry, error) {
	dump := make(map[sfc.CIDRKey]sfc.CIDREntry)
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*sfc.CIDRKey).DeepCopy()
		value := v.(*sfc.CIDREntry).DeepCopy()
		dump[*key] = *value
	}
	stats := bpf.NewDumpStats(sfc.CIDRMap)
	err := sfc.CIDRMap.DumpReliablyWithCallback(cb, stats)
	if err != nil {
		return nil, err
	}
	return dump, nil
}

// Returns existing Select map entries
func existingSelectors() (map[sfc.SelectKey]sfc.PathKey, error) {
	dump := make(map[sfc.SelectKey]sfc.PathKey)
	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*sfc.SelectKey).DeepCopy()
		value := v.(*sfc.PathKey).DeepCopy()
		dump[*key] = *value
	}
	stats := bpf.NewDumpStats(sfc.SelectMap)
	err := sfc.SelectMap.DumpReliablyWithCallback(cb, stats)
	if err != nil {
		return nil, err
	}
	return dump, nil
}

func epLabels(ep *endpoint.Endpoint) (labels.Set, error) {
	identity, err := ep.GetSecurityIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to get identity from ep %d: %v", ep.GetID(), err)
	}
	if identity == nil {
		return nil, identityNotReady{}
	}
	if identity.ID.IsReservedIdentity() {
		return nil, fmt.Errorf("ep %d has reserved identity: %s", ep.GetID(), identity.ID)
	}
	labels := labels.Set(identity.Labels.K8sStringMap())
	return labels, nil
}

func FilteredSvcSelector() cache.ObjectSelector {
	// TODO(optmization): use existing service cache in k8s watcher instead.
	// Watching + caching SFC services should have minimal impact on resource usage.
	return cache.ObjectSelector{
		Label: labels.SelectorFromSet(labels.Set{v1.ManagedByKey: v1.ControllerName}),
	}
}
