#!/bin/bash

# This script is triggered by Prow.
#
# The testing steps are as follows:
# 1. We build cilium/cilium-operator image our of current HEAD.
# 2. We push the images to our testing project's registry.
# 3. We create a GKE cluster in our testing project.
# 4. We run Cilium's e2e tests by pulling from testing project's bucket.

set -ex

date=$(TZ=":America/Los_Angeles" date '+%Y-%m-%d-%H-%M-%S')
CLUSTER_NAME="e2e-cluster-$date"
GKE_ZONE="us-central1-c"
GCR_HOST="gcr.io"

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
  gcloud alpha container clusters create $CLUSTER_NAME --project=$GCP_PROJECT --machine-type=n1-standard-8 --release-channel=rapid --zone $GKE_ZONE
}

function clean_up {
  log "Deleting GKE cluster: " $CLUSTER_NAME
  gcloud alpha container clusters delete $CLUSTER_NAME --project=$GCP_PROJECT --zone $GKE_ZONE || true
}

function make_cilium {
  log "Make Cilium images"
  sh make-images-push-to-local-registry.sh $GCR_HOST/$GCP_PROJECT latest
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
CNI_INTEGRATION=gke K8S_VERSION=$CLUSTER_VERSION CILIUM_IMAGE=$GCR_HOST/$GCP_PROJECT/cilium/cilium:latest CILIUM_OPERATOR_IMAGE=$GCR_HOST/$GCP_PROJECT/cilium/operator:latest ginkgo --focus="K8s*" -noColor -- -cilium.provision=false -cilium.kubeconfig=$(echo ~/.kube/config) -cilium.passCLIEnvironment=true

# Step 5: cleans up.
clean_up
