***************
Unit Test Image
***************

This is the GCE image used for running Cilium's unit tests. It contains
dependencies Cilium needs to run unit tests, including clang, llvm, make,
go, docker, tc, and bpftool.

Prerequisites
=============

install `packer <https://www.packer.io/downloads.html>`_

GCP project

service account that at least has `Compute Engine Instance Admin (v1)` and
`Service Account User` roles

Create an Image
===============

PROJ_ID=<PROJ_ID> \
  SERVICE_ACCT_KEY=<SERVICE_ACCT_KEY> \
  SSH_USERNAME=<SSH_USERNAME> \
  IMAGE_NAME=<IMAGE_NAME> \
  packer build unit-test-env.json

example:
PROJ_ID="gke-anthos-datapath-presubmits" \
  SERVICE_ACCT_KEY="./gke-anthos-datapath-presubmits-868b024a9596.json" \
  SSH_USERNAME="prow" \
  IMAGE_NAME="cilium-unit-test-$(TZ=':America/Los_Angeles' date '+%Y%m%d')" \
  packer build unit-test-env.json

Packer will do the following:
1. Creates a temporary VM on GCE
2. Installs the base image (Debian)
3. Provisions the VM
4. Creates an image named IMAGE_NAME and saves it to GCP
   The new image can be found in `GCP console -> Compute Engine -> Images <https://console.cloud.google.com/compute/images>`_
5. Deletes the temporary VM (regardless of whether step 4 succeeded or not)

The Prow job which triggers unit tests need to be updated with the
new IMAGE_NAME.
