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

echo "===================== Running runEbpfUnitTest.sh ========================="
set -x
set -euo pipefail

trap "{ echo 'Test OS information: ' ;uname -a;}" EXIT

SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")
export TEST_VM_SOURCE_CODE_PATH="$1"

pushd "${TEST_VM_SOURCE_CODE_PATH}" || exit 1

# gcloud is not installed in COS
if command -v gcloud; then
    gcloud auth configure-docker
fi

# Create run.sh
cat <<EOF > run.sh
#!/bin/bash
git config --global --add safe.directory "${TEST_VM_SOURCE_CODE_PATH}"

make -C bpf/tests clean

# TODO(wanlindu): Enable coverage report when upstream
# fix (https://github.com/cilium/cilium/pull/24094) is
# synced in internal repo.
CLANG=clang-10 LLC=llc-10 make -C test run_bpf_tests
EOF
chmod 750 run.sh

IMAGE="$(sudo docker build -q "${SCRIPT_DIR}")"
sudo docker run --privileged --workdir  "${TEST_VM_SOURCE_CODE_PATH}" --entrypoint /bin/bash -v /sys/fs/bpf:/sys/fs/bpf  -v "${TEST_VM_SOURCE_CODE_PATH}:${TEST_VM_SOURCE_CODE_PATH}" "${IMAGE}" "${TEST_VM_SOURCE_CODE_PATH}/run.sh"

popd || exit 0
