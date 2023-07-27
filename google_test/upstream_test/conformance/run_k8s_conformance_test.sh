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

# Set up job variables
SHA="$(git log -1 --format=%H | cut -c -7)"
CILIUM_CLI_VERSION=v0.14.8
K8S_VERSION=v1.27.3
export DOCKER_BUILD_KIT=1
export DOCKER_CLI_EXPERIMENTAL=enabled
export PROJECT="${GCP_PROJECT:-anthos-networking-ci}"
export IMAGE_REGISTRY="gcr.io/${PROJECT}/k8s-conformance-kind"
export CILIUM_TAG=cilium/cilium
export CILIUM_OPERATOR_TAG=cilium/operator
export CILIUM_OPERATOR_GENERIC_TAG=cilium/operator-generic
export HUBBLE_RELAY_TAG=cilium/hubble-relay
export CLUSTERMESH_APISERVER_TAG=cilium/clustermesh-apiserver
export HTTPS_PROXY=http://localhost:8118
export HTTP_PROXY=http://localhost:8118
export ACCOUNT_NAME="anthos-networking-ci-runner@${PROJECT}.iam.gserviceaccount.com"

echo "  ARTIFACTS        = ${ARTIFACTS}"
echo "  KUBETEST2_RUN_ID = ${KUBETEST2_RUN_ID}"

# Register gcloud as the credential helper for Google-supported Docker registries.
gcloud auth configure-docker

# Build and push cilium to local registry at
echo "Making Cilium images for current build and push to local registry: ${IMAGE_REGISTRY}"

make LOCKDEBUG=1 DOCKER_REGISTRY="${IMAGE_REGISTRY}" DOCKER_IMAGE_TAG="${SHA}" docker-cilium-image
docker push "${IMAGE_REGISTRY}/${CILIUM_TAG}:${SHA}"

make -B LOCKDEBUG=1 DOCKER_REGISTRY="${IMAGE_REGISTRY}" DOCKER_IMAGE_TAG="${SHA}" docker-operator-image
docker push "${IMAGE_REGISTRY}/${CILIUM_OPERATOR_TAG}:${SHA}"

make -B LOCKDEBUG=1 DOCKER_REGISTRY="${IMAGE_REGISTRY}" DOCKER_IMAGE_TAG="${SHA}" docker-operator-generic-image
docker push "${IMAGE_REGISTRY}/${CILIUM_OPERATOR_GENERIC_TAG}:${SHA}"

make -B LOCKDEBUG=1 DOCKER_REGISTRY="${IMAGE_REGISTRY}" DOCKER_IMAGE_TAG="${SHA}" docker-clustermesh-apiserver-image
docker push "${IMAGE_REGISTRY}/${CLUSTERMESH_APISERVER_TAG}:${SHA}"

make LOCKDEBUG=1 DOCKER_REGISTRY="${IMAGE_REGISTRY}" DOCKER_IMAGE_TAG="${SHA}" docker-hubble-relay-image
docker push "${IMAGE_REGISTRY}/${HUBBLE_RELAY_TAG}:${SHA}"

# Obtain the kubeconfig and host machine info to access the kind cluster created
for resource_directory in "${ARTIFACTS}/.kubetest2-tailorbird"/*; do
    if [ -d "${resource_directory}" ]; then
        KUBECONFIG=${resource_directory}/terraform-files/kubeconfig.yaml
        echo "KUBECONFIG found in ${resource_directory}/terraform-files/kubeconfig.yaml"
        HOST_MACHINE_INFO_DIR=${resource_directory}/connectivity-metadata
    fi
done

# Access the created kind cluster and get the cluster name
CLUSTER_NAME=$(kubectl config get-contexts --kubeconfig "${KUBECONFIG}" | grep kind- | tr -s ' ' | cut -d " " -f 2 | cut -d "-" -f 2)

# This function installs kind to get logs from kind cluster.
function get_log_from_kind_cluster {
    # Obtain hostmachine ip and username
    HOST_MACHINE_USER="$(jq '.default_transport.attributes.username' "${HOST_MACHINE_INFO_DIR}"/connectivity_metadata.json | tr -d '"')"
    HOST_MACHINE_IP="$(jq '.default_transport.attributes.bastion_hostname' "${HOST_MACHINE_INFO_DIR}"/connectivity_metadata.json | tr -d '"')"
    # Collect kog remotely and copy back to prow job at ${ARTIFACTS}
    KIND_LOGDUMP=/tmp/logdump
    ssh -i "${HOST_MACHINE_INFO_DIR}"/id_rsa -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes "${HOST_MACHINE_USER}@${HOST_MACHINE_IP}" "mkdir -p ${KIND_LOGDUMP} && kind export logs --name ${CLUSTER_NAME} ${KIND_LOGDUMP}"
    scp -i "${HOST_MACHINE_INFO_DIR}"/id_rsa -o StrictHostKeyChecking=accept-new -o IdentitiesOnly=yes -r "${HOST_MACHINE_USER}@${HOST_MACHINE_IP}":"${KIND_LOGDUMP}" "${ARTIFACTS}"
}

function clean_up_before_exit {
    set +e
    # Dump all debug info
    kubectl get pods --all-namespaces -o wide
    cilium status
    cilium sysdump --output-filename cilium-sysdump-final
    mv /home/prow/go/src/gke-internal.googlesource.com/third_party/cilium/cilium-sysdump-final.zip "${ARTIFACTS}"
    # This function get logs from kind cluster.
    get_log_from_kind_cluster
}

trap clean_up_before_exit EXIT

# Remove kube-proxy and kindnet in preparation to install cilium.
kubectl delete ds kube-proxy -n kube-system
kubectl delete ds kindnet -n kube-system

# Generate k8s secret from eligible SA for pulling images from GCR.
export ACCOUNT_KEY=${ACCOUNT_NAME}-key.json
export SECRETNAME=gcr-pull-secret
gcloud secrets versions access latest --secret=anthos-networking-ci-runner-gcr-pull-secret --project="${PROJECT}" > "${ACCOUNT_KEY}"
kubectl create secret generic --type=kubernetes.io/dockerconfigjson -n kube-system "${SECRETNAME}" --from-file=.dockerconfigjson="${ACCOUNT_KEY}"

# Install Cilium CLI
curl -sSL --remote-name-all https://github.com/cilium/cilium-cli/releases/download/"${CILIUM_CLI_VERSION}"/cilium-linux-amd64.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-amd64.tar.gz.sha256sum
tar xzvfC cilium-linux-amd64.tar.gz /usr/local/bin
rm cilium-linux-amd64.tar.gz{,.sha256sum}
cilium version

# Install Cilium into the Kubernetes cluster pointed to by your current kubectl context
cilium install --wait --chart-directory=install/kubernetes/cilium \
    --helm-set=image.repository="${IMAGE_REGISTRY}/${CILIUM_TAG}" \
    --helm-set=image.useDigest=false \
    --helm-set=imagePullSecrets[0].name="${SECRETNAME}" \
    --helm-set=image.tag="${SHA}" \
    --helm-set=operator.image.repository="${IMAGE_REGISTRY}/${CILIUM_OPERATOR_TAG}" \
    --helm-set=operator.image.suffix="" \
    --helm-set=operator.image.tag="${SHA}" \
    --helm-set=operator.image.useDigest=false \
    --helm-set=clustermesh.apiserver.image.repository="${IMAGE_REGISTRY}/${CLUSTERMESH_APISERVER_TAG}" \
    --helm-set=clustermesh.apiserver.image.tag="${SHA}" \
    --helm-set=clustermesh.apiserver.image.useDigest=false \
    --helm-set=hubble.relay.image.repository="${IMAGE_REGISTRY}/${HUBBLE_RELAY_TAG}" \
    --helm-set=hubble.relay.image.tag="${SHA}" \
    --helm-set=cni.chainingMode=portmap \
    --helm-set-string=kubeProxyReplacement=strict \
    --helm-set=sessionAffinity=true \
    --helm-set=bpf.monitorAggregation=none \
    --disable-check=minimum-version \
    --rollback=false

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

# Run tests

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
