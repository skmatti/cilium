#!/bin/bash

# Copyright 2020 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/..
CODEGEN_PKG=${CODEGEN_PKG:-$(cd ${SCRIPT_ROOT}; ls -d -1 ../../vendor/k8s.io/code-generator 2>/dev/null || echo ../../../k8s.io/code-generator)}

[[ -z "$GOPATH" ]] && echo "GOPATH environment variable must be set for code-generator to work." && false

echo "Performing code generation for FQDNNetworkPolicy CRD"
${CODEGEN_PKG}/generate-groups.sh \
  "deepcopy,client,informer,lister" \
  github.com/cilium/cilium/pkg/gke/client/fqdnnetworkpolicy github.com/cilium/cilium/pkg/gke/apis \
  "fqdnnetworkpolicy:v1alpha1" \
  --go-header-file ${SCRIPT_ROOT}/hack/boilerplate.go.txt

echo "Performing code generation for NetworkLogging CRD"
${CODEGEN_PKG}/generate-groups.sh \
  "deepcopy,client,informer,lister" \
  github.com/cilium/cilium/pkg/gke/client/networklogging github.com/cilium/cilium/pkg/gke/apis \
  "networklogging:v1alpha1" \
  --go-header-file ${SCRIPT_ROOT}/hack/boilerplate.go.txt

echo "Performing code generation for RedirectService CRD"
${CODEGEN_PKG}/generate-groups.sh \
  "deepcopy,client,informer,lister" \
  github.com/cilium/cilium/pkg/gke/client/redirectservice github.com/cilium/cilium/pkg/gke/apis \
  "redirectservice:v1alpha1" \
  --go-header-file ${SCRIPT_ROOT}/hack/boilerplate.go.txt

echo "Performing code generation for TrafficSteering CRD"
${CODEGEN_PKG}/generate-groups.sh \
  "deepcopy,client,informer,lister" \
  github.com/cilium/cilium/pkg/gke/client/trafficsteering github.com/cilium/cilium/pkg/gke/apis \
  "trafficsteering:v1alpha1" \
  --go-header-file ${SCRIPT_ROOT}/hack/boilerplate.go.txt

echo "Performing code generation for DataplaneV2Encryption CRD"
${CODEGEN_PKG}/generate-groups.sh \
  "deepcopy" \
  github.com/cilium/cilium/pkg/gke/client/dataplanev2encryption github.com/cilium/cilium/pkg/gke/apis \
  "dataplanev2encryption:v1alpha1" \
  --go-header-file ${SCRIPT_ROOT}/hack/boilerplate.go.txt

echo "Performing code generation for RemoteNode CRD"
${CODEGEN_PKG}/generate-groups.sh \
  "deepcopy,client,informer,lister" \
  github.com/cilium/cilium/pkg/gke/client/remotenode github.com/cilium/cilium/pkg/gke/apis \
  "remotenode:v1alpha1" \
  --go-header-file ${SCRIPT_ROOT}/hack/boilerplate.go.txt
