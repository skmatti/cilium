package k8s

import (
	"fmt"
	"strings"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
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

func GetCEPIndexKeyFrom(obj interface{}, ns string) resource.Key {
	var podName string
	var addr *cilium_v2.EndpointNetworking
	switch cep := obj.(type) {
	case *cilium_v2.CiliumEndpoint:
		podName = cep.Name
		addr = cep.Status.Networking
		for _, ownerRef := range cep.OwnerReferences {
			if ownerRef.Kind == "Pod" {
				podName = ownerRef.Name
				break
			}
		}

	case *cilium_v2alpha1.CoreCiliumEndpoint:
		podName = cep.Name
		addr = cep.Networking
	default:
		return resource.Key{}
	}
	ip := ""
	if addr != nil && len(addr.Addressing) > 0 {
		ip = addr.Addressing[0].IPV4
		if ip == "" {
			ip = addr.Addressing[0].IPV6
		}
		ip = strings.ReplaceAll(ip, ".", "-")
		ip = strings.ReplaceAll(ip, ":", "-")
	}
	return resource.Key{Namespace: ns, Name: truncate(podName, 253-len(ns)-len(ip)) + ip}
}

const CEPIPIndex = "cep_ip_name"

func CEPIndexFunc(obj interface{}) ([]string, error) {
	var ns string
	switch cep := obj.(type) {
	case *cilium_v2.CiliumEndpoint:
		ns = cep.Namespace
	default:
		return nil, fmt.Errorf("only support cilium_v2.CiliumEndpoint but seeing %T", obj)
	}
	key := GetCEPIndexKeyFrom(obj, ns)

	return []string{key.String()}, nil
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
