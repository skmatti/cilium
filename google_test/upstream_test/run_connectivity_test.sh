#!/bin/bash

# Copyright 2023 Google LLC

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

set -ex
set -u
set -o pipefail

echo "---------------- Running connectivity test ---------------------------"
echo "KUBECONFIG = ${KUBECONFIG}"

# generated connectivity manifest files
make -C examples/kubernetes/connectivity-check fmt
make -C examples/kubernetes/connectivity-check all

kubectl apply -f examples/kubernetes/connectivity-check/connectivity-check.yaml
kubectl wait --for=condition=Available --all deployment --timeout=2m
