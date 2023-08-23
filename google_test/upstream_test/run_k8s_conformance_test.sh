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

echo "---------------- Running k8s conformance test ---------------------------"

K8S_VERSION=v1.27.3
echo "KUBECONFIG = ${KUBECONFIG}"
# Run Kubernetes sig-network conformance test
# Kubernetes e2e tests use ginkgo and tags to select the tests that should run based on two regex, focus and skip:
# Focus tests:
# \[Conformance\]|\[sig-network\]: Conformance tests are defined by the project to guarantee a consistent behaviour and some mandatory features on all clusters
#                                  sig-network tests are defined by sig-networkto guarantee a consistent behaviour on all the the k8s network implementations
# Skipped tests:
# Disruptive|Serial : require to run in serial and perform disruptive operations on clusters (reboots, ...)
# Federation|PerformanceDNS : unrelated sig-network tests
# Feature : skip features that are not GA, however, some of them should be enabled, per example [Feature:ProxyTerminatingEndpoints]
# DualStack : only with dualstack clusters
# KubeProxy|kube-proxy : kube-proxy specifics
# LoadBalancer|GCE|ExternalIP : require a cloud provider, some of them are GCE specifics
# Netpol|NetworkPolicy : network policies, demand significant resources and use to be slow, better to run in a different job
# same.port.number.but.different.protocols|HostPort : #9207
# rejected : Kubernetes expect Services without endpoints associated to REJECT the connection to notify the client, Cilium silently drops the packet
# externalTrafficPolicy : needs investigation

# TODO (b/293362837): fix + re-enable failing conformance tests

# Test binaries
TMP_DIR=$(mktemp -d)
curl -L https://dl.k8s.io/"${K8S_VERSION}"/kubernetes-test-linux-amd64.tar.gz -o "${TMP_DIR}"/kubernetes-test-linux-amd64.tar.gz
tar xvzf "${TMP_DIR}"/kubernetes-test-linux-amd64.tar.gz \
    --directory "${TMP_DIR}" \
    --strip-components=3 kubernetes/test/bin/ginkgo kubernetes/test/bin/e2e.test
sudo cp "${TMP_DIR}"/e2e.test /usr/local/bin/e2e.test
sudo cp "${TMP_DIR}"/ginkgo /usr/local/bin/ginkgo

export KUBERNETES_CONFORMANCE_TEST='y'
/usr/local/bin/ginkgo --nodes=25 \
    --focus="\[Conformance\]|\[sig-network\]" \
    --skip="Feature|Federation|PerformanceDNS|DualStack|Disruptive|Serial|KubeProxy|kube-proxy|ExternalIP|LoadBalancer|GCE|Netpol|NetworkPolicy|rejected|externalTrafficPolicy|HostPort|same.port.number.but.different.protocols|should.serve.endpoints.on.same.port.and.different.protocols" \
    --skip="should.support.remote.command.execution.over.websockets" \
    --skip="should.support.a.Service.with.multiple.ports.specified.in.multiple.EndpointSlices" \
    --skip="should.support.retrieving.logs.from.the.container.over.websockets" \
    --skip="should.be.able.to.connect.to.terminating.and.unready.endpoints.if.PublishNotReadyAddresses.is.true" \
    --skip="should.create.endpoints.for.unready.pods" \
    /usr/local/bin/e2e.test \
    -- \
    --kubeconfig="${KUBECONFIG}" \
    --provider=local \
    --dump-logs-on-failure=true \
    --report-dir="${ARTIFACTS}" \
    --disable-log-dump=true
