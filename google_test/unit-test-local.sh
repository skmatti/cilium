#!/bin/bash

# This script is meant to be triggered by presubmit-unit.sh from PROW.
# This runs the actual unit tests of Cilium.
#
# Workflow:
# 1. Installs prerequisites (this will be baked into the image later).
# 2. Changes dir structure to what Cilium's Makefile expects.
# 3. Runs unprivileged tests.
# 4. Changes into root hat.
# 5. Runs privileged tests.

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
}

function allow_docker_op {
  # Hacky workaround before upstream resolves pidfile_test issue.
  sudo chmod 666 /var/run/docker.sock
}

function log {
  echo "`date +'%b %d %T.000'`: INFO: $@"
}

# Getting prerequisites requires privileged ops. Will be removed once deps are
# built in the testing image.
sudo ./cilium/google_test/get-deps.sh || true

# Make make happy.
ch_dir

# Allow non-root docker operations.
allow_docker_op

# Run un-priviledged tests first.
make unit-tests

# Run privileged tests as root.
sudo PATH=$PATH make tests-privileged

EXIT_VALUE=$?

exit $EXIT_VALUE
