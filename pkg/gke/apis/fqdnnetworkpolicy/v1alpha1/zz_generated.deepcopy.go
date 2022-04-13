//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*
Copyright 2023 Google LLC

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

// Code generated by deepcopy-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicy) DeepCopyInto(out *FQDNNetworkPolicy) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicy.
func (in *FQDNNetworkPolicy) DeepCopy() *FQDNNetworkPolicy {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicy)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FQDNNetworkPolicy) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicyEgressRule) DeepCopyInto(out *FQDNNetworkPolicyEgressRule) {
	*out = *in
	if in.Matches != nil {
		in, out := &in.Matches, &out.Matches
		*out = make([]FQDNNetworkPolicyMatch, len(*in))
		copy(*out, *in)
	}
	if in.Ports != nil {
		in, out := &in.Ports, &out.Ports
		*out = make([]FQDNNetworkPolicyPort, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicyEgressRule.
func (in *FQDNNetworkPolicyEgressRule) DeepCopy() *FQDNNetworkPolicyEgressRule {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicyEgressRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicyList) DeepCopyInto(out *FQDNNetworkPolicyList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]FQDNNetworkPolicy, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicyList.
func (in *FQDNNetworkPolicyList) DeepCopy() *FQDNNetworkPolicyList {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicyList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *FQDNNetworkPolicyList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicyMatch) DeepCopyInto(out *FQDNNetworkPolicyMatch) {
	*out = *in
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicyMatch.
func (in *FQDNNetworkPolicyMatch) DeepCopy() *FQDNNetworkPolicyMatch {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicyMatch)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicyPort) DeepCopyInto(out *FQDNNetworkPolicyPort) {
	*out = *in
	if in.Port != nil {
		in, out := &in.Port, &out.Port
		*out = new(int32)
		**out = **in
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicyPort.
func (in *FQDNNetworkPolicyPort) DeepCopy() *FQDNNetworkPolicyPort {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicyPort)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *FQDNNetworkPolicySpec) DeepCopyInto(out *FQDNNetworkPolicySpec) {
	*out = *in
	in.PodSelector.DeepCopyInto(&out.PodSelector)
	if in.Egress != nil {
		in, out := &in.Egress, &out.Egress
		*out = make([]FQDNNetworkPolicyEgressRule, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new FQDNNetworkPolicySpec.
func (in *FQDNNetworkPolicySpec) DeepCopy() *FQDNNetworkPolicySpec {
	if in == nil {
		return nil
	}
	out := new(FQDNNetworkPolicySpec)
	in.DeepCopyInto(out)
	return out
}
