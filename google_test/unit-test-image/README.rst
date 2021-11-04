***************
Unit Test Image
***************

This is the GCE image used for running Cilium's unit tests. It contains
dependencies Cilium needs to run unit tests, including clang, llvm, make,
go, docker, tc, and bpftool.

Prerequisites
=============

install `packer <https://www.packer.io/downloads.html>`_, ver >= 1.7.8

GCP project

You must at least have `Compute Engine Instance Admin (v1)` and
`Service Account User` roles in the project of gke-anthos-datapath-presubmits.

Create an Image
===============

PROJ_ID=<PROJ_ID> \
  SSH_USERNAME=<SSH_USERNAME> \
  IMAGE_NAME=<IMAGE_NAME> \
  packer build unit-test-env.json

example:

PROJ_ID="gke-anthos-datapath-presubmits" \
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
new IMAGE_NAME in `google_test/presubmit-unit.sh`.
