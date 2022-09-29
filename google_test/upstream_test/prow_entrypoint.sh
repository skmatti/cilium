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

TIMESTAMP=$(TZ=:America/Los_Angeles date +%Y-%m-%d-%H-%M-%S)

# Set up the Project, Zone and name for test VM.
PROJECT="${GCP_PROJECT:-gke-anthos-datapath-presubmits}"
ZONE=us-west1-b
TEST_VM_NAME="prow-${BUILD_ID}-${TIMESTAMP}-$(git rev-parse --short=5 HEAD)-ttl1d"
TEST_VM_MACHINE_TYPE="${TEST_VM_MACHINE_TYPE:-n2-highcpu-32}"

# Set up the OS images to create test VM, the script default to run upstream runtime and e2e test.
IMAGE_PROJECT="${IMAGE_PROJECT:-ubuntu-os-cloud}"
IMAGE_FAMILY="${IMAGE_FAMILY:-ubuntu-minimal-2004-lts}"

# Set up defaults for test specific ENV varaibles and scripts.
TEST_TYPE="${TEST_TYPE:-upstream_e2e_test}"
TEST_SPECIFIC_RUN_TEST_SCRIPT="${TEST_SPECIFIC_RUN_TEST_SCRIPT:-google_test/upstream_test/runE2ETest.sh}"

ARTIFACTS="${ARTIFACTS:-/logs/artifacts}"
PROW_INTERNAL_SOURCE_CODE_PATH="${PROW_INTERNAL_SOURCE_CODE_PATH:-/home/prow/go/src/gke-internal.googlesource.com/third_party/cilium/}"
PROW_UPSTREAM_SOURCE_CODE_PATH="${PROW_UPSTREAM_SOURCE_CODE_PATH:-/home/prow/go/src/upstream-cilium/}"

TEST_RESULTS_NAME="${TEST_RESULTS_NAME:-"junit_result_${TEST_TYPE}.xml"}"
TEST_VM_WORKDIR="${TEST_VM_WORKDIR:-/home/prow}"
TEST_VM_INTERNAL_SOURCE_CODE_PATH="${TEST_VM_WORKDIR}/cilium"
TEST_VM_UPSTREAM_SOURCE_CODE_PATH="${TEST_VM_WORKDIR}/upstream-cilium"

function log {
    echo "INFO: $(date +'%b %d %T.000') $*"
}

function clone_upstream_cilium_code_to_prow {
    log 'Cloneing upstream source code to prow.'
    mkdir -p "${PROW_UPSTREAM_SOURCE_CODE_PATH}"
    pushd "${PROW_UPSTREAM_SOURCE_CODE_PATH}"|| exit 1
    git clone --recursive https://github.com/cilium/cilium.git .
    git checkout "${UPSTREAM_CILIUM_BRANCH}"
    git submodule update --init
    go mod vendor
    COMMIT_SHA=$(git rev-parse "${UPSTREAM_CILIUM_BRANCH}")
    echo "COMMIT SHA: ${COMMIT_SHA}"
    popd || exit 0
}

# Set the test specific ENV varaibles and scripts.
if [[ "${IMAGE_PROJECT}" = anthos-baremetal-ci ]] || [[ "${IMAGE_PROJECT}" = cos-cloud ]]; then
    log "Running ebpf test with ${IMAGE_FAMILY}"
    TEST_TYPE="ebpf_${IMAGE_FAMILY}"
    TEST_SPECIFIC_RUN_TEST_SCRIPT=google_test/upstream_test/runEbpfUnitTest.sh
    TEST_RESULTS_NAME=bpf-coverage.html
    TEST_VM_MACHINE_TYPE=n2-highcpu-2
fi

UPSTREAM_CILIUM_BRANCH="${UPSTREAM_CILIUM_BRANCH:-}"
if [[ -z "${UPSTREAM_CILIUM_BRANCH}" ]]; then
    log "Running test on internal Cilium repo."
else
    log "Running test on upstream Cilium repo with ${UPSTREAM_CILIUM_BRANCH}."
    clone_upstream_cilium_code_to_prow
fi

echo "Running TEST_TYPE = ${TEST_TYPE}"
echo "TEST_VM_NAME = ${TEST_VM_NAME}"
echo "PROJECT = ${PROJECT}"
echo "ZONE = ${ZONE}"
echo "IMAGE_PROJECT = ${IMAGE_PROJECT}"
echo "IMAGE_FAMILY = ${IMAGE_FAMILY}"
echo "TEST_VM_WORKDIR = ${TEST_VM_WORKDIR}"
echo "TEST_SPECIFIC_RUN_TEST_SCRIPT = ${TEST_SPECIFIC_RUN_TEST_SCRIPT}"
echo "TEST_RESULTS_NAME = ${TEST_RESULTS_NAME}"

function auth {
    # This is set through:
    # https://gke-internal.googlesource.com/test-infra/+/refs/heads/master/prow/gob/config.yaml#36
    log 'Activating service account.'
    gcloud auth activate-service-account --key-file="${GOOGLE_APPLICATION_CREDENTIALS}"
}

# Create ssh policy for the project.
function allow_ssh {
    log 'Creating FW ssh-all.'
    gcloud compute firewall-rules create ssh-all --project "${PROJECT}"  --allow tcp:22 || true
}

# Create GCE instance with specific OS image, with the nested virtualization enabled
function create_gce_instance_with_os {
    log "Creating gce instance with OS image: IMAGE_PROJECT = ${IMAGE_PROJECT}, IMAGE_FAMILY = ${IMAGE_FAMILY} to run ${TEST_TYPE} test."
    gcloud components update
    gcloud compute instances create "${TEST_VM_NAME}" \
        --project "${PROJECT}" --zone "${ZONE}" \
        --enable-nested-virtualization \
        --metadata-from-file=startup-script=./google_test/countdown-and-self-destruct.sh \
        --image-project="${IMAGE_PROJECT}" \
        --image-family="${IMAGE_FAMILY}" \
        --machine-type="${TEST_VM_MACHINE_TYPE}" \
        --boot-disk-size=256GB
}

function clean_up_gce_instance {
    log "Deleting GCE instance ${TEST_VM_NAME}.${ZONE}.${PROJECT}."
    gcloud compute instances delete "${TEST_VM_NAME}" --quiet --project="${PROJECT}" --zone="${ZONE}"  || true
}

function copy_code_from_prow_to_test_vm {
    local source_code_path=$1
    log 'Copying test source code from job pod to GCE test VM.'
    go mod vendor || true
    gcloud compute scp --recurse --project="${PROJECT}" --zone="${ZONE}" "${source_code_path}" "${TEST_VM_NAME}:${TEST_VM_WORKDIR}/"
}

function run_test_script_in_vm {
    log "Running ${TEST_SPECIFIC_RUN_TEST_SCRIPT} in ${TEST_VM_NAME}.${ZONE}.${PROJECT}."
    gcloud compute ssh "${TEST_VM_NAME}" --project "${PROJECT}" --zone "${ZONE}" --command="/bin/bash ${TEST_VM_INTERNAL_SOURCE_CODE_PATH}/${TEST_SPECIFIC_RUN_TEST_SCRIPT} ${*@Q}"

}

function copy_back_report {
    log "Copying the test report back to ${ARTIFACTS}."
    for path in "$@"
    do
        gcloud compute scp --project "${PROJECT}" --zone "${ZONE}" "${TEST_VM_NAME}:${path}" "${ARTIFACTS}" || true
    done
}

auth

allow_ssh

create_gce_instance_with_os

trap clean_up_gce_instance EXIT

# Internal source code is always copied for test scrips.
copy_code_from_prow_to_test_vm "${PROW_INTERNAL_SOURCE_CODE_PATH}"

if [[ -z "${UPSTREAM_CILIUM_BRANCH}" ]]; then
    run_test_script_in_vm "${TEST_VM_INTERNAL_SOURCE_CODE_PATH}"
    copy_back_report "${TEST_VM_INTERNAL_SOURCE_CODE_PATH}/${TEST_RESULTS_NAME}"
else
    copy_code_from_prow_to_test_vm "${PROW_UPSTREAM_SOURCE_CODE_PATH}"
    run_test_script_in_vm "${TEST_VM_UPSTREAM_SOURCE_CODE_PATH}"
    copy_back_report "${TEST_VM_UPSTREAM_SOURCE_CODE_PATH}/${TEST_RESULTS_NAME}"
fi
