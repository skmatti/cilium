package controller

import (
	ciliumLbls "github.com/cilium/cilium/pkg/labels"
)

func k8sPrefix(in map[string]string) map[string]string {
	k8sMap := make(map[string]string)
	for k, v := range in {
		k8sMap["k8s."+k] = v
	}
	return k8sMap
}

func int32Ptr(i int32) *int32 { return &i }

func labelLess(a, b ciliumLbls.Label) bool {
	if a.Key != b.Key {
		return a.Key < b.Key
	}
	if a.Value != b.Value {
		return a.Value < b.Value
	}
	return a.Source < b.Source
}
