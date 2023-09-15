#!/bin/bash -e

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

date=$(TZ=":America/Los_Angeles" date '+%Y-%m-%d-%H-%M-%S')
PROJECT="${GCP_PROJECT:-gke-anthos-datapath-presubmits}"
VM_NAME="prow-unit-$date-$(git rev-parse --short=5 HEAD)-ttl1d"
ZONE="us-west1-b"
MACHINE_TYPE="c2-standard-8"
HOST_NAME="$VM_NAME.$ZONE.$PROJECT"

function log {
  echo "$(date +'%b %d %T.000'): INFO:  $@"
}

function error {
  echo "$(date +'%b %d %T.000'): ERROR: $@"
  exit 1
}

function auth {
  # This is set through:
  # https://gke-internal.googlesource.com/test-infra/+/refs/heads/master/prow/gob/config.yaml#36
  log "Activating service account"
  gcloud auth activate-service-account --key-file=$GOOGLE_APPLICATION_CREDENTIALS
  gcloud config set project $PROJECT
  gcloud config set compute/zone $ZONE
}

function provision_vm {
  log "Provisioning GCE VM " $VM_NAME
  trap clean_up_vm EXIT
  gcloud compute instances create ${VM_NAME} \
    --image-project=ubuntu-os-cloud \
    --image-family=ubuntu-minimal-2004-lts \
    --machine-type=$MACHINE_TYPE \
    --boot-disk-type=pd-ssd \
    --boot-disk-size=64GB \
    --metadata-from-file=startup-script=./google_test/countdown-and-self-destruct.sh \
    --metadata-from-file=user-data=./google_test/unit-test-image/userdata.yaml \
    --scopes=compute-rw || exit 1
  wait_for_vm
  gcloud compute config-ssh
}

function wait_for_vm {
  local count=0
  until gcloud compute ssh --quiet root@$VM_NAME --command="cloud-init status --wait" 2> /dev/null; do
    if (( count++ >= 5 )); then
      error "Failed to create $VM_NAME, reached the retry limit";
    fi
    log "Waiting $count second(s) for $VM_NAME to be ready"
    sleep $count
  done
  log "$VM_NAME is ready"
}

function clean_up_vm {
  log "Deleting GCE instance " $VM_NAME
  gcloud compute instances delete ${VM_NAME} --quiet
}

function ship_repo {
  log "Shipping repo to target GCE instance " $HOST_NAME
  rsync -avzq . root@$HOST_NAME:/root/cilium
}

function allow_ssh {
  log "Creating FW ssh-all"
  gcloud compute firewall-rules create ssh-all --allow tcp:22 || true
}

function rexec {
  local cmd=$@
  log "Running remote cmd " $cmd " on instance " $HOST_NAME
  ssh root@$HOST_NAME "$cmd"
}

auth

allow_ssh

provision_vm

ship_repo

rexec "cd cilium; make install-go"
rexec "cd cilium; ./google_test/unit-test-local.sh"
