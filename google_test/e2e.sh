#!/bin/bash

# Copyright 2020 Google LLC

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

# This script is triggered by Prow.
#
# The general testing flow is like the following:
# 1. We build cilium/cilium-operator image our of current HEAD.
# 2. We push the images to our testing project's registry.
# 3. We create a GKE cluster in our testing project.
# 4. We run Cilium's e2e tests by pulling from testing project's bucket.
#
# Caveats:
# The testing e2e clusters will be teared down upon successful runs.
# For jobs that are abnormally terminated (maybe due to a bug), the cluster
# will remain live for 1d from its creation time and will reclaimed upon
# next job.

set -x

timestamp=$(TZ=":America/Los_Angeles" date '+%Y-%m-%d-%H-%M-%S')
CLUSTER_NAME="prow-e2e-$timestamp-ttl1d"
GKE_ZONE="us-central1-c"
GCR_HOST="gcr.io"
CILIUM_TAG="latest-e2e"

function log {
  echo "`date +'%b %d %T.000'`: INFO: $@"
}

function auth {
  # This is set through:
  # https://gke-internal.googlesource.com/test-infra/+/refs/heads/master/prow/gob/config.yaml#36
  log "Activating service account"
  gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS
}

function auth_docker {
  cat $GOOGLE_APPLICATION_CREDENTIALS | docker login -u _json_key --password-stdin https://$GCR_HOST
}

function provision_GKE_cluster {
  log "Provisioning GKE cluster: " $CLUSTER_NAME
  gcloud alpha container clusters create $CLUSTER_NAME --project=$GCP_PROJECT --machine-type=n1-standard-8 --release-channel=rapid --zone $GKE_ZONE --num-nodes=2
}

function reclaim_hanging_resources {
  log "Deleting old GKE clusters if there are any"
  # Get current time in UTC since this is what gcloud describe returns in.
  cur=$(date -u '+%Y-%m-%d %H:%M:%S')
  old_clusters=($(gcloud container clusters list --project=$GCP_PROJECT | awk '{if (NR!=1) {print $1}}'))
  for c in "${old_clusters[@]}"
  do
    creation_time=$(gcloud container clusters describe $c --project $GCP_PROJECT --zone $GKE_ZONE | grep createTime | awk -F "'" '{print $2}' | sed 's/T/ /g' | awk -F "+" '{print $1}')
    t1=$(date --date "$creation_time" +%s)
    t2=$(date --date "$cur" +%s)
    diff=$((t2 - t1))
    # Set a lifespan of 1d, which leaves roughly 18h for debugging before reclaiming the resources.
    lifespan=$((3600 * 24))
    if [ "$diff" -gt "$lifespan" ]; then
      log "Deleting old GKE cluster: " $c
      gcloud container clusters delete $c --project $GCP_PROJECT --zone $GKE_ZONE --quiet
    fi
  done

  log "Deleting old images"
  gcloud container images list-tags gcr.io/$GCP_PROJECT/cilium/cilium --filter='-tags:*' --format='get(digest)' --limit=unlimited | awk '{print "gcr.io/'$GCP_PROJECT'/cilium/cilium@" $1}' | xargs gcloud container images delete --quiet  || true
  gcloud container images list-tags gcr.io/$GCP_PROJECT/cilium/cilium-dev --filter='-tags:*' --format='get(digest)' --limit=unlimited | awk '{print "gcr.io/'$GCP_PROJECT'/cilium/cilium-dev@" $1}' | xargs gcloud container images delete --quiet || true
  gcloud container images list-tags gcr.io/$GCP_PROJECT/cilium/operator --filter='-tags:*' --format='get(digest)' --limit=unlimited | awk '{print "gcr.io/'$GCP_PROJECT'/cilium/operator@" $1}' | xargs gcloud container images delete --quiet || true
}

function clean_up {
  log "Deleting GKE cluster: " $CLUSTER_NAME
  gcloud alpha container clusters delete $CLUSTER_NAME --project=$GCP_PROJECT --zone $GKE_ZONE || true
}

function make_cilium {
  log "Make Cilium images"
  sh make-images-push-to-local-registry.sh $GCR_HOST/$GCP_PROJECT $CILIUM_TAG
}

function get_deps {
  go get github.com/onsi/ginkgo/ginkgo
  go get github.com/onsi/gomega/...

   curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3
   chmod 700 get_helm.sh
   ./get_helm.sh
}

function setup_gke_env {
  log "getting kubeconfig for $CLUSTER_NAME"
  gcloud alpha container clusters get-credentials --project=$GCP_PROJECT --zone $GKE_ZONE $CLUSTER_NAME
  CLUSTER_VERSION=$(gcloud container clusters list --project $GCP_PROJECT --zone $GKE_ZONE --filter "name:${CLUSTER_NAME}" | awk '{print $3}' | grep -v MASTER_VERSION | sed -E 's/([0-9]+\.[0-9]+)\..*/\1/')
  kubectl create namespace cilium
  NODES=($(kubectl get nodes --no-headers -o custom-columns=":metadata.name"))
  if [ "${#NODES[@]}" -lt 2 ]; then
        echo "Must have at least 2 nodes in testing cluster."
        exit 1
  fi
  knode1=${NODES[0]}
  knode2=${NODES[1]}
  log "labeling $knode1"
  kubectl label node $knode1 cilium.io/ci-node=k8s1
  log "labeling $knode2"
  kubectl label node $knode2 cilium.io/ci-node=k8s2
}

trap clean_up EXIT INT TERM

reclaim_hanging_resources

cd test

# Step 0: sorts out permission.
auth
auth_docker

# Step 1: builds cilium images.
make_cilium

# Step 2: creates testing cluster.
provision_GKE_cluster

# Step 3: acquires test cluster envs.
setup_gke_env

# Step 4: runs tests.
get_deps
CNI_INTEGRATION=gke K8S_VERSION=$CLUSTER_VERSION CILIUM_IMAGE=$GCR_HOST/$GCP_PROJECT/cilium/cilium:$CILIUM_TAG CILIUM_OPERATOR_IMAGE=$GCR_HOST/$GCP_PROJECT/cilium/operator:$CILIUM_TAG ginkgo --focus="K8s*" -noColor -- -cilium.provision=false -cilium.kubeconfig=$(echo ~/.kube/config) -cilium.passCLIEnvironment=true

# Step 5: rename/move result junit xml for testgrid.
mv k8s-$CLUSTER_VERSION.xml ${ARTIFACTS}/junit_k8s-$CLUSTER_VERSION.xml

# Step 6: cleans up.
clean_up
