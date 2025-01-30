#!/bin/bash

# Copyright 2024 Google LLC

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

# This script is triggered by Louhi/dev.
#
# The general testing flow is like the following:
# 1. We build cilium/cilium-operator image out of current HEAD.
# 2. We push the images to our testing project's registry.
# 3. We create a GKE cluster in our testing project.
# 4. We run Cilium's e2e tests.
#
# Caveats:
# The testing e2e clusters will be teared down upon successful runs.
# For jobs that are abnormally terminated (maybe due to a bug), the cluster
# will remain live for 1d from its creation time and will be reclaimed upon
# next job.
# You can skip cluster deletion by setting SKIP_DELETE=y
#
# Example execution:
# GPROXY=gproxy GCP_PROJECT=gke-1n-dev GCP_PROJECT_NUM=157897283967 CILIUM_TAG=28.999.0 ./google_test/1n_e2e.sh

set -x
set -e

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

timestamp=$(TZ=":America/Los_Angeles" date '+%Y-%m-%d-%H-%M-%S')
CLUSTER_NAME="prow-e2e-$timestamp-ttl1d"
GKE_LOCATION="${GKE_LOCATION:-us-central1}"
GCR_HOST="gcr.io"
CILIUM_TAG="${CILIUM_TAG:-29.999.999}"

export CLOUDSDK_API_ENDPOINT_OVERRIDES_CONTAINER=https://test-container.sandbox.googleapis.com/
GCLOUD_CONTAINER="gcloud alpha container"
GPROXY=${GPROXY:-/gproxy}

GCP_PROJECT=${GCP_PROJECT:-gke-1n-dev}
GCP_PROJECT_NUM=${GCP_PROJECT_NUM:-157897283967}
MESH_ID="mesh-${CILIUM_TAG//./-}"

TEMP="$(mktemp -d)"
export KUBECONFIG="$TEMP/kubeconfig"

# TODO(b/315934702): add meshes/negs to reclaim_hanging_resources

function log {
  echo "`date +'%b %d %T.000'`: INFO: $@"
}

function provision_GKE_cluster {
  log "Provisioning GKE cluster: " $CLUSTER_NAME
  ${GPROXY} --patch='{"cluster": {"components": {"desired_components": [{"component_reference": {"component": "advanceddatapath", "version": "'${CILIUM_TAG}'"}, "test_only_component_image": "us-central1-docker.pkg.dev/'${GCP_PROJECT}'/gke-component-images/advanceddatapath:'${CILIUM_TAG}'"}]}}}' \
    -- ${GCLOUD_CONTAINER} clusters create $CLUSTER_NAME \
    --project=$GCP_PROJECT \
    --machine-type=n1-standard-8 \
    --release-channel=rapid \
    --location $GKE_LOCATION \
    --enable-ip-alias \
    --enable-dataplane-v2 \
    --num-nodes=2 \
    --cluster-version=1.32 \
    --scopes https://www.googleapis.com/auth/cloud-platform
}

function reclaim_hanging_resources {
  log "Deleting old GKE clusters if there are any"
  # Get current time in UTC since this is what gcloud describe returns in.
  cur=$(date -u '+%Y-%m-%d %H:%M:%S')
  old_clusters=($(${GCLOUD_CONTAINER} clusters list --location $GKE_LOCATION --project=$GCP_PROJECT | awk '{if (NR!=1) {print $1}}'))
  for c in "${old_clusters[@]}"
  do
    creation_time=$(${GCLOUD_CONTAINER} clusters describe $c --project $GCP_PROJECT --location $GKE_LOCATION | grep createTime | awk -F "'" '{print $2}' | sed 's/T/ /g' | awk -F "+" '{print $1}')
    t1=$(date --date "$creation_time" +%s)
    t2=$(date --date "$cur" +%s)
    diff=$((t2 - t1))
    lifespan=$((3600 * 24 * 7)) # 7 days
    if [ "$diff" -gt "$lifespan" ]; then
      log "Deleting old GKE cluster: " $c
      ${GCLOUD_CONTAINER} clusters delete $c --project $GCP_PROJECT --location $GKE_LOCATION --quiet
    fi
  done

  log "Deleting old images"
  gcloud container images list-tags gcr.io/$GCP_PROJECT/cilium/cilium --filter='-tags:*' --format='get(digest)' --limit=unlimited | awk '{print "gcr.io/'$GCP_PROJECT'/cilium/cilium@" $1}' | xargs gcloud container images delete --quiet  || true
  gcloud container images list-tags gcr.io/$GCP_PROJECT/cilium/cilium-dev --filter='-tags:*' --format='get(digest)' --limit=unlimited | awk '{print "gcr.io/'$GCP_PROJECT'/cilium/cilium-dev@" $1}' | xargs gcloud container images delete --quiet || true
  gcloud container images list-tags gcr.io/$GCP_PROJECT/cilium/operator --filter='-tags:*' --format='get(digest)' --limit=unlimited | awk '{print "gcr.io/'$GCP_PROJECT'/cilium/operator@" $1}' | xargs gcloud container images delete --quiet || true
}

function clean_up {
  test -z ${SKIP_DELETE} || return
  test -d "${TEMP}" || return

  log "Deleting GKE cluster: " $CLUSTER_NAME
  ${GCLOUD_CONTAINER} clusters delete --project "$GCP_PROJECT" --location "$GKE_LOCATION" --quiet "${CLUSTER_NAME}" || true

  rm -rf "${TEMP}"
}

function get_deps {
  pushd "${SCRIPT_DIR}/wora"
  test -x "$(which ginkgo)" || {
    go install github.com/onsi/ginkgo/v2/ginkgo
  }
  popd
}

function make_cilium {
  log "Make Cilium images"
  DOCKER_FLAGS="--push" DOCKER_IMAGE_TAG=${CILIUM_TAG} DOCKER_REGISTRY=gcr.io/${GCP_PROJECT} make docker-cilium-image
}

function override_image_in_component {
  log "overriding advanceddatapath component image"
  docker build --build-arg project_id=${GCP_PROJECT} --build-arg tag=${CILIUM_TAG} --build-arg mesh_id=${MESH_ID} -t us-central1-docker.pkg.dev/${GCP_PROJECT}/gke-component-images/advanceddatapath:${CILIUM_TAG} - < "${SCRIPT_DIR}/1n/Dockerfile-override-without-pika"
  docker push us-central1-docker.pkg.dev/${GCP_PROJECT}/gke-component-images/advanceddatapath:${CILIUM_TAG}
}

trap clean_up EXIT INT TERM

test -z "${DELETE_OLD}" || reclaim_hanging_resources

make_cilium

override_image_in_component

provision_GKE_cluster

get_deps

pushd "${SCRIPT_DIR}/wora"
ginkgo \
  -v \
  --keep-going \
  --timeout=2h \
  --no-color \
  --output-dir="${TEMP}" \
  --flake-attempts=3 \
  "./" -- \
  --project-id "${GCP_PROJECT}" \
  --project-num "${GCP_PROJECT_NUM}" \
  --mesh "${MESH_ID}"
popd

clean_up
