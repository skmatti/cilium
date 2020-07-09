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

# This script is meant to be triggered by presubmit-unit.sh from PROW.
# This runs the actual unit tests of Cilium.
#
# Workflow:
# 1. Changes dir structure to what Cilium's Makefile expects.
# 2. Runs unprivileged tests.
# 3. Changes into root hat.
# 4. Runs privileged tests.

set -xe

export GOROOT=/usr/local/go
export GOPATH=/go
export PATH=$GOROOT/bin:$GOPATH/bin:$GOPATH/src/github.com/cilium/cilium/bpf:$PATH

function ch_dir {
  # This contructs the expected dir tree to make Cilium's Makefile happy.
  # pwd: /home/prow/
  sudo rm -r $GOPATH/src/github.com/cilium || true
  sudo mkdir -p $GOPATH/src/github.com/cilium/
  sudo mv cilium/ $GOPATH/src/github.com/cilium/
  cd $GOPATH/src/github.com/cilium/cilium
  log $(pwd)
}

function allow_docker_op {
  # Hacky workaround before upstream resolves pidfile_test issue.
  sudo chmod 666 /var/run/docker.sock
}

function log {
  echo "`date +'%b %d %T.000'`: INFO: $@"
}

# Make make happy.
ch_dir

# Allow non-root docker operations.
allow_docker_op

# Run prechecks including golang fmt check and bpf prog compilcation first.
make ci-precheck

# Run un-priviledged tests first.
make unit-tests

# Run privileged tests as root.
sudo PATH=$PATH make tests-privileged

EXIT_VALUE=$?

exit $EXIT_VALUE
