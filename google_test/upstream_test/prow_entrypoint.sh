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

# This script is triggered by Prow to privison the single VM to run upstream
# Cilium test.
set -x
set -euo pipefail

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

# TEST_SPECIFIC_RUN_TEST_SCRIPT is determined from TEST_TYPE. For TEST_TYPE=experiment,
# it is set instead to the the value of TEST_SPECIFIC_RUN_TEST_SCRIPT.
declare -A test_script_from_test_type=(
  [ebpf]=google_test/upstream_test/ebpf/run_ebpf_tests.sh
  [experiment]="${TEST_SPECIFIC_RUN_TEST_SCRIPT:-}"
)

# VM machine type is determined from TEST_VM_MACHINE_TYPE. Default is determined
# by TEST_TYPE. For TEST_TYPE=experiment, there is no default, and the type
# must be set explicitly.
declare -A test_vm_machine_type_from_test_type=(
  [ebpf]="${TEST_VM_MACHINE_TYPE:-e2-standard-4}"
  [experiment]="${TEST_VM_MACHINE_TYPE:-}"
)

# Make test fail fast if TEST_TYPE is not specified.
if [[ -z "${TEST_TYPE}" ]]; then
  echo "TEST_TYPE must be set."
  exit 1
fi

run_test_script="${test_script_from_test_type["${TEST_TYPE}"]}"

test_vm_machine_type="${test_vm_machine_type_from_test_type["${TEST_TYPE}"]}"

# Make test fail fast if run test script or machine type cannot be determined.
if [[ -z "${run_test_script}" || -z "${test_vm_machine_type}" ]]; then
  echo "Cannot determine test script or machine type from test type."
  echo "TEST_TYPE=${TEST_TYPE}"
  if [[ "${TEST_TYPE}" != experiment ]]; then
    echo "Valid choices for TEST_TYPE are:" "${!test_script_from_test_type[@]}"
  else
    echo "The following variables must be set for TEST_TYPE=experiment:"
    echo "TEST_SPECIFIC_RUN_TEST_SCRIPT=${TEST_SPECIFIC_RUN_TEST_SCRIPT}"
    echo "TEST_VM_MACHINE_TYPE=${TEST_VM_MACHINE_TYPE}"
  fi
  exit 1
fi

# Make test fail fast if IMAGE_PROJECT or the IMAGE_FAMILY and IMAGE_REF is not specified.
IMAGE_FAMILY="${IMAGE_FAMILY:-}"
IMAGE_REF="${IMAGE_REF:-}"
if [[ -z ${IMAGE_PROJECT} ]] || { [[ -z ${IMAGE_FAMILY} ]] && [[ -z ${IMAGE_REF} ]]; }; then
  log "Please specify IMAGE_PROJECT and IMAGE_FAMILY or IMAGE_REF."
  exit 1
fi

TIMESTAMP=$(TZ=:America/Los_Angeles date +%Y-%m-%d-%H-%M-%S)

# Set up the Project, Zone and name for test VM.
PROJECT="${GCP_PROJECT:-gke-anthos-datapath-presubmits}"
ZONE=us-west1-b
TEST_VM_NAME="prow-${BUILD_ID}-${TIMESTAMP}-$(git rev-parse --short=5 HEAD)-ttl1d"
HOST_NAME="$TEST_VM_NAME.$ZONE.$PROJECT"
ARTIFACTS="${ARTIFACTS:-/logs/artifacts}"
PROW_INTERNAL_SOURCE_CODE_PATH="${PROW_INTERNAL_SOURCE_CODE_PATH:-/home/prow/go/src/gke-internal.googlesource.com/third_party/cilium/}"
PROW_UPSTREAM_SOURCE_CODE_PATH="${PROW_UPSTREAM_SOURCE_CODE_PATH:-/home/prow/go/src/upstream-cilium/}"

TEST_VM_WORKDIR="${TEST_VM_WORKDIR:-/home/prow/src}"
TEST_VM_INTERNAL_SOURCE_CODE_PATH="${TEST_VM_WORKDIR}/cilium"
TEST_VM_UPSTREAM_SOURCE_CODE_PATH="${TEST_VM_WORKDIR}/upstream-cilium"

function log {
  echo "INFO: $(date +'%b %d %T.000') $*"
}

function error {
  echo "ERROR: $(date +'%b %d %T.000') $*"
  exit 1
}

function clone_upstream_cilium_code_to_prow {
  log 'Cloneing upstream source code to prow.'
  mkdir -p "${PROW_UPSTREAM_SOURCE_CODE_PATH}"
  pushd "${PROW_UPSTREAM_SOURCE_CODE_PATH}" || exit 1
  git clone --recursive https://github.com/cilium/cilium.git .
  git checkout "${UPSTREAM_CILIUM_BRANCH}"
  git submodule update --init
  go mod vendor
  COMMIT_SHA=$(git rev-parse "${UPSTREAM_CILIUM_BRANCH}")
  echo "COMMIT SHA: ${COMMIT_SHA}"
  popd || exit 0
}

UPSTREAM_CILIUM_BRANCH="${UPSTREAM_CILIUM_BRANCH:-}"
if [[ -z "${UPSTREAM_CILIUM_BRANCH}" ]]; then
  log "Running test on internal Cilium repo."
else
  log "Running test on upstream Cilium repo with ${UPSTREAM_CILIUM_BRANCH}."
  clone_upstream_cilium_code_to_prow
fi

echo "Run test script: ${run_test_script}"
echo "Test VM machine type: ${test_vm_machine_type}"
echo "TEST_VM_NAME = ${TEST_VM_NAME}"
echo "PROJECT = ${PROJECT}"
echo "ZONE = ${ZONE}"
echo "IMAGE_PROJECT = ${IMAGE_PROJECT}"
echo "IMAGE_FAMILY = ${IMAGE_FAMILY}"
echo "IMAGE_REF = ${IMAGE_REF}"

function auth {
  # This is set through:
  # https://gke-internal.googlesource.com/test-infra/+/refs/heads/master/prow/gob/config.yaml#36
  log 'Activating service account.'
  gcloud auth activate-service-account --key-file="${GOOGLE_APPLICATION_CREDENTIALS}"
  gcloud config set project "${PROJECT}"
  gcloud config set compute/zone "${ZONE}"
}

# Create ssh policy for the project.
function allow_ssh {
  log 'Creating FW ssh-all.'
  gcloud compute firewall-rules create ssh-all --allow tcp:22 || true
}

# Create GCE instance with specific OS image
function create_gce_instance_with_os {
  log "Creating gce instance with OS image: IMAGE_PROJECT = ${IMAGE_PROJECT}, IMAGE_FAMILY = ${IMAGE_FAMILY}, IMAGE_REF = ${IMAGE_REF} to run ${TEST_TYPE} test."
  if [[ -n "${IMAGE_REF}" ]]; then
    gcloud beta compute instances create "${TEST_VM_NAME}" \
      --max-run-duration 24h \
      --instance-termination-action=DELETE \
      --image-project="${IMAGE_PROJECT}" \
      --image="${IMAGE_REF}" \
      --machine-type="${test_vm_machine_type}" \
      --boot-disk-size=256GB
  else
    gcloud beta compute instances create "${TEST_VM_NAME}" \
      --max-run-duration 24h \
      --instance-termination-action=DELETE \
      --image-project="${IMAGE_PROJECT}" \
      --image-family="${IMAGE_FAMILY}" \
      --machine-type="${test_vm_machine_type}" \
      --boot-disk-size=256GB
  fi
  wait_for_vm
  wait_for_config_ssh
}

function wait_for_vm {
  local count=0
  until gcloud compute ssh --quiet "${TEST_VM_NAME}" --command="echo ready" 2>/dev/null; do
    if ((count++ >= 5)); then
      error "Failed to create ${TEST_VM_NAME}, reached the retry limit"
    fi
    log "Waiting $count second(s) for ${TEST_VM_NAME} to be ready"
    sleep $count
  done
  log "${TEST_VM_NAME} is ready"
}

function wait_for_config_ssh {
  local count=0
  until gcloud compute config-ssh 2>/dev/null; do
    if ((count++ >= 5)); then
      error "Failed to configure SSH for GCP VMs, reached the retry limit"
    fi
    log "Waiting $count second(s) to configure SSH for GCP VMs"
    sleep $count
  done
  log "Configured SSH for GCP VMs"
}

function copy_back_report {
  log "Copying the test report back to ${ARTIFACTS}."
  for path in "$@"; do
    scp "prow@${HOST_NAME}:${path}/*" "${ARTIFACTS}" || true
  done
}

function clean_up_gce_instance {
  log "Deleting GCE instance ${TEST_VM_NAME}.${ZONE}.${PROJECT}."
  gcloud compute instances delete "${TEST_VM_NAME}" --quiet || true
}

function remove_symlinks_in_repo {
  local repo_path=$1
  log "Remove symlinks in ${repo_path}, since they are not supported by scp."
  find "${repo_path}" -mindepth 1 -type l -print0 | xargs -r0 rm
}

function copy_code_from_prow_to_test_vm {
  local source_code_path=$1
  log 'Copying test source code from job pod to GCE test VM.'
  scp -r "${source_code_path}" "prow@${HOST_NAME}:${TEST_VM_WORKDIR}/"
}

function rexec {
  local cmd=$*
  log "Running remote cmd ${cmd} on instance ${TEST_VM_NAME}"
  ssh "prow@${HOST_NAME}" "$cmd"
}

auth

allow_ssh

create_gce_instance_with_os

trap clean_up_gce_instance EXIT

# For gdch-rocky, the permission for the created directory needs to be set to 777.
rexec "sudo mkdir -p ${TEST_VM_INTERNAL_SOURCE_CODE_PATH}; sudo mount -o size=8G -t tmpfs none ${TEST_VM_INTERNAL_SOURCE_CODE_PATH}; sudo chmod -R 777 ${TEST_VM_WORKDIR}"
# For edgeos, the docker service is shutdown by default.
rexec "sudo systemctl start docker"

# Internal source code is always copied for test scrips, taking the source code
# path in prow as input.
remove_symlinks_in_repo "${PROW_INTERNAL_SOURCE_CODE_PATH}"
copy_code_from_prow_to_test_vm "${PROW_INTERNAL_SOURCE_CODE_PATH}"

# TEST_VM_SOURCE_CODE_PATH is the path of code under test, the test source code
# path is internal cilium code by default, change the path to upstream for
# upstream testing.
TEST_VM_SOURCE_CODE_PATH="${TEST_VM_INTERNAL_SOURCE_CODE_PATH}"
if [[ -n "${UPSTREAM_CILIUM_BRANCH}" ]]; then
  rexec "sudo mkdir -p ${TEST_VM_UPSTREAM_SOURCE_CODE_PATH}; sudo mount -o size=8G -t tmpfs none ${TEST_VM_UPSTREAM_SOURCE_CODE_PATH}; sudo chmod -R 777 ${TEST_VM_WORKDIR}"
  remove_symlinks_in_repo "${PROW_UPSTREAM_SOURCE_CODE_PATH}"
  copy_code_from_prow_to_test_vm "${PROW_UPSTREAM_SOURCE_CODE_PATH}"
  TEST_VM_SOURCE_CODE_PATH="${TEST_VM_UPSTREAM_SOURCE_CODE_PATH}"
fi

# TEST_VM_RESULTS_DIR, is where the test reports are stored inside the VM,
# at the end of the test the junit reports will be copied back to prow and
# uploaded. This path is used to depend on the path of source code under test.
TEST_VM_RESULTS_DIR="${TEST_VM_RESULTS_DIR:-${TEST_VM_SOURCE_CODE_PATH}/test_results}"

echo "TEST_VM_SOURCE_CODE_PATH = ${TEST_VM_SOURCE_CODE_PATH}"
echo "TEST_VM_RESULTS_DIR=${TEST_VM_RESULTS_DIR}"

rexec "${TEST_VM_INTERNAL_SOURCE_CODE_PATH}/${run_test_script} ${TEST_VM_SOURCE_CODE_PATH}" "${TEST_VM_RESULTS_DIR}"
copy_back_report "${TEST_VM_RESULTS_DIR}"
