package k8s

import (
	"cmp"
	"fmt"
	"strings"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
)

var (
	replacer = strings.NewReplacer(":", "-", ".", "-")
)

// GetPodNameIfExistsFromCiliumEndpoint returns the name of the pod associated
// with the cilium endpoint
func GetPodNameIfExistsFromCiliumEndpoint(cep interface{}) string {
	switch concreteCEP := cep.(type) {
	case *cilium_v2.CiliumEndpoint:
		for _, ownerRef := range concreteCEP.OwnerReferences {
			if ownerRef.Kind == "Pod" {
				return ownerRef.Name
			}
		}
		return concreteCEP.Name
	case *types.CiliumEndpoint:
		for _, ownerRef := range concreteCEP.OwnerReferences {
			if ownerRef.Kind == "Pod" {
				return ownerRef.Name
			}
		}
		return concreteCEP.Name
	}
	return ""
}

// CEPKey creates a resource Key from the endpoint.
func CEPKey(obj v2.NetworkingEndpoint, ns string) resource.Key {
	// TODO(b/366189069): remove nil check.
	if obj == nil {
		return resource.Key{}
	}
	var (
		podName = obj.GetName()
		addr    = obj.GetNetworking()
	)
	if cep, ok := obj.(*cilium_v2.CiliumEndpoint); ok {
		for _, ownerRef := range cep.OwnerReferences {
			if ownerRef.Kind == "Pod" {
				podName = ownerRef.Name
				break
			}
		}
	}

	if addr == nil || len(addr.Addressing) == 0 {
		return resource.Key{Namespace: ns, Name: podName}
	}

	return resource.Key{Namespace: ns, Name: multinetCEPName(podName, addr.Addressing[0])}
}

const CEPIPIndex = "cep_ip_name"

func CEPIndexFunc(obj any) ([]string, error) {
	cep, ok := obj.(*cilium_v2.CiliumEndpoint)
	if !ok {
		return nil, fmt.Errorf("only v2.CiliumEndpoint is supported but seeing %T", obj)
	}
	key := CEPKey(cep, cep.Namespace)

	return []string{key.String()}, nil
}

// multinetCEPName produces a multi-networking compliant CEP object name.
// This ensures that CEPs belonging to the same Pod are unique.
func multinetCEPName(name string, pair *cilium_v2.AddressPair) string {
	ip := replacer.Replace(cmp.Or(pair.IPV4, pair.IPV6))
	return truncate(name, 253-len(ip)) + ip
}

func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[0:length]
}

// MaybePodOwner returns the namespaced/name of the Pod that owns the CEP.
// If no owner is found, returns an empty string.
func MaybePodOwnerFor(cep *types.CiliumEndpoint) string {
	for _, ownerRef := range cep.OwnerReferences {
		if ownerRef.Kind == "Pod" {
			return strings.TrimLeft(cep.Namespace+"/"+ownerRef.Name, "/")
		}
	}
	return ""
}
