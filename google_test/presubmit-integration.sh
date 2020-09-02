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

# This is triggered by PROW upon code change.
# The process is like below:
# 1. Fire up Prow job using host container image
# 2. Start integration test with testing VM image via ENV to vagrant.
#    2.1. Ships over source code (via rsync).
#    2.2. Compiles and installs cilium.
#    2.3. Accepts ssh requests from host to run tests.

set -x
timestamp=$(TZ=":America/Los_Angeles" date '+%Y-%m-%d-%H-%M-%S')
PROJECT="${GCP_PROJECT:-gke-anthos-datapath-presubmits}"
VM_NAME="prow-runtime-$timestamp-$(git rev-parse --short=5 HEAD)-ttl1d"
SSH_DUMMY="dummy-$timestamp"
ZONE="us-west1-b"
HOST_NAME="$VM_NAME.$ZONE.$PROJECT"
TESTING_IMAGE="cilium-runtime-test-kernel-5-3-20200831"

function log {
  echo "`date +'%b %d %T.000'`: INFO: $@"
}

function auth {
  # This is set through:
  # https://gke-internal.googlesource.com/test-infra/+/refs/heads/master/prow/gob/config.yaml#36
  log "Activating service account"
  gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS
}

function setup_vagrant_user {
  log "Creating dummy vm"
  gcloud compute instances create $SSH_DUMMY --project ${PROJECT} --zone ${ZONE} --metadata-from-file=startup-script=./google_test/countdown-and-self-destruct.sh --scopes=compute-rw

  log "Creating key-pair for vagrant user"
  gcloud compute ssh vagrant@$SSH_DUMMY --project ${PROJECT} --zone ${ZONE} --command="exit"

  log "Deleting dummy vm"
  gcloud compute instances delete $SSH_DUMMY --project ${PROJECT} --zone ${ZONE}
}

function allow_SSH {
  log "Creating FW ssh-all"
  gcloud compute firewall-rules create ssh-all --project ${PROJECT}  --allow tcp:22 || true
}

function clean_up {
  log "Deleteing GCE instance " $VM_NAME
  gcloud compute instances delete ${VM_NAME} --quiet --project=${PROJECT} --zone=$ZONE || true
}

function rexec {
  local cmd=$@
  log "Running remote cmd " $cmd " on instance " $HOST_NAME
  gcloud compute ssh $VM_NAME --project $PROJECT --zone $ZONE --command="$cmd"
}

function log {
  echo "`date +'%b %d %T.000'`: INFO: $@"
}

function preserve_log {
  VAGRANT_VAGRANTFILE="../google_test/runtime_test/gce-vagrantfile" \
    PROJ_ID=$PROJECT \
    ZONE=$ZONE \
    SERVICE_ACCT_KEY=$GOOGLE_APPLICATION_CREDENTIALS \
    IMAGE=$TESTING_IMAGE \
    VAGRANT_SSH_KEY="~/.ssh/google_compute_engine" \
    INSTANCE_NAME=$VM_NAME \
    METADATA_KEY1="startup-script" \
    METADATA_VAL1=$(cat ../google_test/countdown-and-self-destruct.sh) \
    SCOPES_VAL1="compute-rw" \
    vagrant ssh runtime -c "journalctl -u cilium.service --no-pager" > ${ARTIFACTS}/cilium.log

  mv test_results ${ARTIFACTS}

  mv runtime.xml ${ARTIFACTS}/junit_runtime.xml
}

auth

allow_SSH

setup_vagrant_user

cd test

# TODO: enable RuntimeVerifier when it start supporting the latest kernels
VAGRANT_VAGRANTFILE="../google_test/runtime_test/gce-vagrantfile" \
  PROJ_ID=$PROJECT \
  ZONE=$ZONE \
  SERVICE_ACCT_KEY=$GOOGLE_APPLICATION_CREDENTIALS \
  IMAGE=$TESTING_IMAGE \
  VAGRANT_SSH_KEY="~/.ssh/google_compute_engine" \
  INSTANCE_NAME=$VM_NAME \
  METADATA_KEY1="startup-script" \
  METADATA_VAL1=$(cat ../google_test/countdown-and-self-destruct.sh) \
  SCOPES_VAL1="compute-rw" \
  ginkgo -v -noColor --focus="Runtime*" -skip="RuntimeVerifier|Init Policy"

EXIT_VALUE=$?

preserve_log

clean_up

exit $EXIT_VALUE
