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

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/../../.."
CODEGEN_PKG=${CODEGEN_PKG:-$(cd "${SCRIPT_ROOT}"; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../code-generator)}

source "${CODEGEN_PKG}/kube_codegen.sh"

TMPDIR=$(mktemp -d)
trap 'rm -rf ${TMPDIR}' EXIT

API_GROUPS=(
  "flowtrace:v1alpha1"
  "fqdnnetworkpolicy:v1alpha1"
  "networklogging:v1alpha1"
  "redirectservice:v1alpha1"
  "remotenode:v1alpha1"
  "trafficsteering:v1alpha1"
)

for group in "${API_GROUPS[@]}"; do
  API_NAME=$(echo "${group}" | cut -d: -f1)
  API_VERSION=$(echo "${group}" | cut -d: -f2)
  echo "Performing code generation for ${API_NAME} CRD"
  kube::codegen::gen_client \
      "./pkg/gke/apis" \
      --one-input-api "${API_NAME}/${API_VERSION}" \
      --with-watch \
      --output-dir "${TMPDIR}/github.com/cilium/cilium/pkg/gke/client" \
      --output-pkg "github.com/cilium/cilium/pkg/gke/client" \
      --boilerplate "${SCRIPT_ROOT}/pkg/gke/hack/boilerplate.go.txt"
done

mkdir -p ./pkg/gke/client/
cp -r "${TMPDIR}/github.com/cilium/cilium/pkg/gke/client/." ./pkg/gke/client/

echo "Generating helpers for pkg/gke/apis"
kube::codegen::gen_helpers \
    --boilerplate "${SCRIPT_ROOT}/pkg/gke/hack/boilerplate.go.txt" \
    "${SCRIPT_ROOT}/pkg/gke/apis"
