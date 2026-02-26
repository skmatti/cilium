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

# Config git client for Prow to pull source code.
if [[ -n "${GIT_HTTP_COOKIEFILE}" ]]; then
  echo "Add git config from prow cookie"
  git config --global user.name "${GIT_USER_NAME}"
  git config --global user.email "${GIT_USER_EMAIL}"
  git config --global http.cookiefile "${GIT_HTTP_COOKIEFILE}"

  echo "Add gerrit redirects to git config"
  git config --add --global url."https://gke-internal.googlesource.com".insteadOf sso://gke-internal.git.corp.google.com
  git config --add --global url."https://gke-internal.googlesource.com".insteadOf sso://gke-internal
  git config --add --global url."https://gke-internal.googlesource.com".insteadOf https://gke-internal.git.corp.google.com
  git config --add --global url."https://gke-internal.googlesource.com".insteadOf git://gke-internal.git.corp.google.com
  git config --add --global url."https://gke-internal.googlesource.com".insteadOf git://gke-internal.googlesource.com
  git config --add --global url."https://gke-internal.googlesource.com".insteadOf git+ssh://gke-internal.git.corp.google.com
  git config --add --global url."https://gke-internal.googlesource.com".insteadOf git+ssh://gke-internal.googlesource.com
  git config --add --global url."https://gke-internal.googlesource.com".insteadOf ssh://gke-internal.git.corp.google.com
  git config --add --global url."https://gke-internal.googlesource.com".insteadOf ssh://gke-internal.googlesource.com
  git config --add --global url."https://gke-internal.googlesource.com".insteadOf sso://gke-internal.googlesource.com
  export GOPRIVATE='*.googlesource.com,*.git.corp.google.com'
fi

SHA="$(git rev-parse --verify HEAD)"
export DOCKER_IMAGE_TAG="${SHA}"
export DOCKER_BUILD_KIT=1
export DOCKER_CLI_EXPERIMENTAL=enabled
export PROJECT="${GCP_PROJECT:-anthos-networking-ci}"
export IMAGE_REGISTRY="gcr.io/${PROJECT}"
export CILIUM_IMAGE_REPOSITORY="${IMAGE_REGISTRY}/cilium/cilium"
export CILIUM_IMAGE_TAG="${DOCKER_IMAGE_TAG}-dpv2"
export CILIUM_OPERATOR_IMAGE_REPOSITORY="${IMAGE_REGISTRY}/cilium/operator"
export CILIUM_OPERATOR_GENERIC_IMAGE_REPOSITORY="${IMAGE_REGISTRY}/cilium/operator-generic"
export HUBBLE_RELAY_IMAGE_REPOSITORY="${IMAGE_REGISTRY}/cilium/hubble-relay"
export CLUSTERMESH_APISERVER_IMAGE_REPOSITORY="${IMAGE_REGISTRY}/cilium/clustermesh-apiserver"

# Register gcloud as the credential helper for Google-supported Docker registries.
gcloud auth configure-docker --quiet
gcloud auth configure-docker "${IMAGE_REGISTRY%%/*}" --quiet

function build_and_push_if_absent {
    local image="${1:?}"
    local target="${2:?}"
    local image_registry="${3:?}"
    if gcloud container images describe "${image}" > /dev/null 2>&1; then
        echo "Found: ${image}, skip building"
    else
        echo "${image} not available"
        make -B LOCKDEBUG=1 DOCKER_REGISTRY="${image_registry}" "${target}"
        docker push "${image}"
    fi
}

declare -A images_to_check
operator_image="${CILIUM_OPERATOR_IMAGE_REPOSITORY}:${DOCKER_IMAGE_TAG}"
operator_generic_image="${CILIUM_OPERATOR_GENERIC_IMAGE_REPOSITORY}:${DOCKER_IMAGE_TAG}"
cilium_image="${CILIUM_IMAGE_REPOSITORY}:${CILIUM_IMAGE_TAG}"
clustermesh_image="${CLUSTERMESH_APISERVER_IMAGE_REPOSITORY}:${DOCKER_IMAGE_TAG}"
hubble_image="${HUBBLE_RELAY_IMAGE_REPOSITORY}:${DOCKER_IMAGE_TAG}"

images_to_check["${operator_image}"]="docker-operator-image"
images_to_check["${operator_generic_image}"]="docker-operator-generic-image"
images_to_check["${cilium_image}"]="docker-cilium-dpv2-image"
images_to_check["${clustermesh_image}"]="docker-clustermesh-apiserver-image"
images_to_check["${hubble_image}"]="docker-hubble-relay-image"

# Build and push cilium to google cloud registry
echo "Making Cilium images for current build and push to google cloud registry: ${IMAGE_REGISTRY}"

for image in "${!images_to_check[@]}"; do
    build_and_push_if_absent "${image}" "${images_to_check[${image}]}" "${IMAGE_REGISTRY}"
done

# Get credentials to use tailorbird and create the kind cluster
echo "Getting credentials for tailorbird-prod..."
gcloud container clusters get-credentials tailorbird-prod \
  --region us-west2 --project tailorbird

SA_KEY="anthos-networking-ci-runner@${PROJECT}.iam.gserviceaccount.com-key.json"
gcloud secrets versions access latest --secret=anthos-networking-ci-runner-gcr-pull-secret --project="${PROJECT}" >"${SA_KEY}"

ROOKERY_CONFIG="${ROOKERY_CONFIG:-google_test/upstream_test/tailorbird/rookery-kind.yaml}"

SA_KEY="${SA_KEY}" \
DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG}" \
CILIUM_IMAGE_TAG="${CILIUM_IMAGE_TAG}" \
CILIUM_IMAGE_REPOSITORY="${CILIUM_IMAGE_REPOSITORY}" \
CILIUM_OPERATOR_IMAGE_REPOSITORY="${CILIUM_OPERATOR_IMAGE_REPOSITORY}" \
CLUSTERMESH_APISERVER_IMAGE_REPOSITORY="${CLUSTERMESH_APISERVER_IMAGE_REPOSITORY}" \
HUBBLE_RELAY_IMAGE_REPOSITORY="${HUBBLE_RELAY_IMAGE_REPOSITORY}" \
kubetest2-tailorbird \
  --verbose \
  --up --down \
  --tbconfig "${ROOKERY_CONFIG}" \
  --test exec -- \
  ./google_test/upstream_test/run_tailorbird_general.sh
