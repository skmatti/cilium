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

# This is triggered by Prow upon code change.
# The process is like below:
#
# 1. This script starts on Prow.
# 2. Authenticates PROW SA (which has been granted editor role of target GCP
#    project).
# 3. Creates needed resources (VM) in target GCP project.
# 4. Ships synced gob repo to target VM.
# 5. Remote executes `unit-test-local.sh` on target VM.
# 6. Exit with exit code from remote execution.
#
# Caveats:
# Testing VMs will be automatically torn down after succesful runs. If
# the testing job is terminated early, these VMs will be left alive for 1d
# from the creation time and then self-destruct.

set -x
date=$(TZ=":America/Los_Angeles" date '+%Y-%m-%d-%H-%M-%S')
PROJECT="${GCP_PROJECT:-gke-anthos-datapath-presubmits}"
VM_NAME="prow-unit-$date-$(git rev-parse --short=5 HEAD)-ttl1d"
ZONE="us-west1-b"
HOST_NAME="$VM_NAME.$ZONE.$PROJECT"
tarball=gob_cilium.tar.gz
TESTING_IMAGE=cilium-unit-test-20210303

function log {
  echo "`date +'%b %d %T.000'`: INFO: $@"
}

function auth {
  # This is set through:
  # https://gke-internal.googlesource.com/test-infra/+/refs/heads/master/prow/gob/config.yaml#36
  log "Activating service account"
  gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS
}

function provision_GCE_VM {
  log "Provisioning GCE VM " $VM_NAME
  gcloud compute instances create ${VM_NAME} --project=${PROJECT} --image $TESTING_IMAGE --zone=$ZONE --metadata-from-file=startup-script=./google_test/countdown-and-self-destruct.sh --scopes=compute-rw || exit 1
}

function clean_up {
  log "Deleteing GCE instance " $VM_NAME
  gcloud compute instances delete ${VM_NAME} --quiet --project=${PROJECT} --zone=$ZONE || true
}

function ship_repo {
  log "tarballing repo"
  tar -czf ~/$tarball .
  log "Shipping repo to target GCE instance " $HOST_NAME
  gcloud compute scp ~/$tarball --project $PROJECT --zone $ZONE $VM_NAME:~
}

function allow_SSH {
  log "Creating FW ssh-all"
  gcloud compute firewall-rules create ssh-all --project ${PROJECT}  --allow tcp:22 || true
}

function rexec {
  local cmd=$@
  log "Running remote cmd " $cmd " on instance " $HOST_NAME
  gcloud compute ssh $VM_NAME --project $PROJECT --zone $ZONE --command="$cmd"
}

function log {
  echo "`date +'%b %d %T.000'`: INFO: $@"
}

auth

allow_SSH

provision_GCE_VM

ship_repo

rexec sudo rm -r "~/cilium/" || true
rexec mkdir -p "~/cilium/"
rexec tar -xzf "~/$tarball" -C "~/cilium/"
rexec "cd ~ && ./cilium/google_test/unit-test-local.sh"

EXIT_VALUE=$?

clean_up

exit $EXIT_VALUE
