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
echo "============ Running local provision of the test VM.====================="
set -x
set -euo pipefail

# Install virtualbox and vagrant
sudo apt update && sudo apt install -y tmux vim rsync software-properties-common nfs-common nfs-kernel-server coreutils
sudo apt install -y virtualbox
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository -y "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt update && sudo apt install -y vagrant

# Install dev tools
sudo apt install build-essential git clang llvm docker docker-compose python3-pip -y

# Install go and dependencies
sudo add-apt-repository ppa:longsleep/golang-backports -y && sudo apt update && sudo apt install golang-go -y
PATH=${PATH}:/usr/local/go/bin:$(go env GOPATH)/bin
export PATH

# Install ginkgo
go install -mod=mod github.com/onsi/ginkgo/ginkgo
go install -mod=mod github.com/onsi/gomega

TEST_RESULTS_NAME=${TEST_RESULTS_NAME:-junit_upstream_result.xml}

pushd "$1/test" || exit 1
vagrant destroy runtime || true
KERNEL=net-next ginkgo --focus=Runtime --tags=integration_tests -v --failFast=false -- -cilium.provision=true -cilium.timeout=150m -cilium.runQuarantined=false
popd || exit 0
