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

# This script is triggered by Prow in a trigger based presubmit:
# gke-advanced-datapath-presubmit-ebpf-new-os-evaluation to enable
# experiment Cilium test. You can edit IMAGE_PROJECT and IMAGE_FAMILY below to
# run the test on a custom platform (for instance, to test ebpf tests on a new
# OS or OS version).

set -x
set -euo pipefail

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")

if [[ "${TEST_TYPE}" != experiment ]]; then
    echo "Currently running an experiment. TEST_TYPE must be set to 'experiment'."
    echo "TEST_TYPE=${TEST_TYPE}"
    exit 1
fi

# Edit the lines below to set the OS image to create a test VM. This script
# requires the image to be set explicitly.
IMAGE_PROJECT= # Set your own image project here.
IMAGE_FAMILY= # Set your own image family here.
TEST_VM_MACHINE_TYPE= # Set your own test machine type, for example: n2-highcpu-2

if [[ -z "${IMAGE_PROJECT}" ]] || [[ -z "${IMAGE_FAMILY}" ]] || [[ -z "${TEST_VM_MACHINE_TYPE}" ]]; then
    echo "The following variables must be set explicitly to run ${SCRIPT_NAME}:"
    echo "IMAGE_PROJECT=${IMAGE_PROJECT}"
    echo "IMAGE_FAMILY=${IMAGE_FAMILY}"
    echo "TEST_VM_MACHINE_TYPE=${TEST_VM_MACHINE_TYPE}"
    exit 1
fi

IMAGE_PROJECT=${IMAGE_PROJECT} IMAGE_FAMILY=${IMAGE_FAMILY} TEST_VM_MACHINE_TYPE=${TEST_VM_MACHINE_TYPE} /bin/bash "${SCRIPT_DIR}"/prow_entrypoint.sh
