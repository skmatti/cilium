#!/bin/bash

# This is triggered by PROW upon code change.
# The process is like below:
#
# 1. This script starts on PROW.
# 2. Authenticates PROW SA (which has been granted editor role of target GCP
#    project).
# 3. Creates needed resources (VM) in target GCP project.
# 4. Ships synced gob repo to target VM.
# 5. Remote executes `unit-test-local.sh` on target VM.
# 6. Exit with exit code from remote execution.

set -x
date=$(TZ=":America/Los_Angeles" date '+%Y-%m-%d-%H-%M-%S')
PROJECT="${GCP_PROJECT:-gke-anthos-datapath-presubmits}"
VM_NAME="presubmit-unit-$date"
ZONE="us-west1-b"
HOST_NAME="$VM_NAME.$ZONE.$PROJECT"
tarball=gob_cilium.tar.gz

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
  gcloud compute instances create ${VM_NAME} --project=${PROJECT} --zone=$ZONE --metadata-from-file=startup-script=./google_test/countdown-and-self-destruct.sh --scopes=compute-rw || exit 1
}

function allow_SSH {
  log "Creating FW ssh-all"
  gcloud compute firewall-rules create ssh-all --project ${PROJECT}  --allow tcp:22 || true
}

function clean_up {
  log "Deleteing FW instance ssh-all"
  gcloud compute firewall-rules delete ssh-all --quiet --project ${PROJECT} || true
  log "Deleteing GCE instance " $VM_NAME
  gcloud compute instances delete ${VM_NAME} --quiet --project=${PROJECT} --zone=$ZONE || true
}

function ship_repo {
  log "tarballing repo"
  tar -czf ~/$tarball .
  log "Shipping repo to target GCE instance " $HOST_NAME
  gcloud compute scp ~/$tarball --project $PROJECT --zone $ZONE $VM_NAME:~
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

provision_GCE_VM

allow_SSH

ship_repo

rexec sudo rm -r "~/cilium/" || true
rexec mkdir -p "~/cilium/"
rexec tar -xzf "~/$tarball" -C "~/cilium/"
rexec "cd ~ && ./cilium/google_test/unit-test-local.sh"

EXIT_VALUE=$?

clean_up

exit $EXIT_VALUE
