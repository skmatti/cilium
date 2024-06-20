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

set -x
set -uo pipefail

trap "{ echo 'Test OS information: ' ;uname -a;}" EXIT

export PATH="/usr/local/clang/bin:${PATH}"
export TEST_VM_SOURCE_CODE_PATH="$1"
export TEST_RESULTS_DIR_ON_VM="${2:-$1/test_results}"

# gcloud is not installed in COS
if command -v gcloud; then
    gcloud auth configure-docker
fi

# Make the result dir
mkdir -p "${TEST_RESULTS_DIR_ON_VM}"

cd "${TEST_VM_SOURCE_CODE_PATH}" || exit 1

GOLANG_IMAGE=$(grep -m1 GOLANG_IMAGE Makefile.defs.google | cut -d ' ' -f3)
TEST_IMAGE="$(sudo docker build --build-arg GOLANG_IMAGE="${GOLANG_IMAGE}" -q google_test/upstream_test/ebpf)"

# The following tests are disabled because they only pass on newer kernel versions:
# xdp, session_affinity, ipv6_test: XDP programs, not supported
# ipsec, 13_dev: not supported, tc_lxc_policy_drop: not supported.
# TODO(b/307798164): add these programs back when we make upsream test compatible
# with order kernels.
SKIP_TESTS="xdp|session_affinity|ipsec|ipv6_test|13_dev|tc_lxc_policy_drop"

function run_ebpf_unit_test {
    echo "==================== Running run_ebpf_unit_test =========================="
    # Create run.sh
    cat <<EOF >run.sh
    #!/bin/bash
    set -x
    set -euo pipefail
    git config --global --add safe.directory "${TEST_VM_SOURCE_CODE_PATH}"
    make -C bpf/tests clean
    make -C bpf/tests all
    # The make target does not support skipping particular tests. Before
    # deprecation of all the older kernels, we will skip these tests by running
    # the go test directly.
    # V=1 make -C test run_bpf_tests 2>&1 | tee ebpf_unit_test.txt
    go test -v ./bpf/tests/bpftest -exec sudo -bpf-test-path "${PWD}"/bpf/tests -skip "/($SKIP_TESTS)" 2>&1 | tee ebpf_unit_test.txt
EOF
    chmod 777 run.sh
    # Run test
    sudo docker run --privileged --workdir "${TEST_VM_SOURCE_CODE_PATH}" --entrypoint /bin/bash -v /sys/fs/bpf:/sys/fs/bpf -v "${TEST_VM_SOURCE_CODE_PATH}:${TEST_VM_SOURCE_CODE_PATH}" "${TEST_IMAGE}" "${TEST_VM_SOURCE_CODE_PATH}/run.sh"
    return $?
}

function run_ebpf_complexity_test {
    echo "=================== Running run_ebpf_complexity_test ====================="
    KERNEL_VERSION=$(./gke/hack/complexity-profile.sh)
    sudo docker run -t --privileged --entrypoint go -e CGO_ENABLED=0 -v /sys/fs/bpf:/sys/fs/bpf -v "${TEST_VM_SOURCE_CODE_PATH}:/cilium" -w "/cilium/test/verifier" "${TEST_IMAGE}" test -v -parallel=1 -cilium-base-path /cilium -ci-kernel-version "${KERNEL_VERSION}" 2>&1 | tee ebpf_complexity_test.txt
    return $?
}

if run_ebpf_unit_test; then
    UNIT_EXITCODE=0
else
    UNIT_EXITCODE=1
fi

if run_ebpf_complexity_test; then
    COMPLEXITY_EXITCODE=0
else
    COMPLEXITY_EXITCODE=1
fi

# go-junit-report tool is installed in TEST_IMAGE
if [ -f ebpf_unit_test.txt ]; then
    sudo docker run --entrypoint go-junit-report -v "${TEST_VM_SOURCE_CODE_PATH}:${TEST_VM_SOURCE_CODE_PATH}" -w "${TEST_VM_SOURCE_CODE_PATH}" "${TEST_IMAGE}" -set-exit-code -in ebpf_unit_test.txt -iocopy -out "${TEST_RESULTS_DIR_ON_VM}"/junit_ebpf_unit_test.xml
fi

if [ -f ebpf_complexity_test.txt ]; then
    sudo docker run --entrypoint go-junit-report -v "${TEST_VM_SOURCE_CODE_PATH}:${TEST_VM_SOURCE_CODE_PATH}" -w "${TEST_VM_SOURCE_CODE_PATH}" "${TEST_IMAGE}" -set-exit-code -in ebpf_complexity_test.txt -iocopy -out "${TEST_RESULTS_DIR_ON_VM}"/junit_ebpf_complexity_test.xml
fi

# TODO(b/289105968) separate the ebpf unit test and complexity test.
if [[ ! ${UNIT_EXITCODE} = 0 ]] || [[ ! ${COMPLEXITY_EXITCODE} = 0 ]]; then
    exit 1
fi
