#!/bin/bash

set -o errexit

ROOT=$(dirname "${BASH_SOURCE[0]}")

echo
echo "==============================================================================="
echo "Starting WORA test execution"

function log_finish() {
  if [[ -n "${WORA_ARTIFACTS}" ]] && [[ -n "${TEST_RUN_ID}" ]]; then
    rm "${WORA_ARTIFACTS}/${TEST_RUN_ID}/junit_runner.xml"
  fi
  set +o xtrace
  echo "==============================================================================="
  echo "End of WORA test execution"
  echo
}
trap log_finish exit

set -o xtrace

# Derive semi-unique id for rookery containing test application.
TEST_RUN_ID=${KUBETEST2_RUN_ID:-unset-id}-${BASHPID}

# Revert KUBECONFIG change made by kt2-tb, to avoid control plane login to mess up SUT cluster's kubeconfig.
if [[ -n "${ARTIFACTS}" ]] && [[ "${KUBECONFIG#"${ARTIFACTS}"}" != "${KUBECONFIG}" ]]; then
  export KUBECONFIG="${OLD_KUBECONFIG}"
fi

# Resolve symlink to work around OOB artifact packaging bug.
# Symlink value should point to a cluster's artifact folder against which test will run.
CLUSTER_ARTIFACTS=$(readlink -f "${ARTIFACTS}/.tailorbird/artifacts/knests/wora-sample/clusters/wora-sample")

# Folder for nested WORA runs, to make file layout more clear.
WORA_ARTIFACTS="${ARTIFACTS}/wora"

# Upload-external-clusters name should match namePrefix in WORA yaml.
# Because test is going to have its own junit.xml, suppress kt2 junit generation.
# Status-check-interval is increased to work around incorrect calculation of rookery status.
ARTIFACTS="${WORA_ARTIFACTS}" \
  kubetest2-tailorbird \
  --verbose \
  --run-id "${TEST_RUN_ID}" \
  --tbenv="${TBENV:-int}" \
  --tbconfig "${ROOT}/wora_k8s_conformance.yaml" \
  --upload-external-clusters "oob=${CLUSTER_ARTIFACTS}" \
  --status-check-interval=90 \
  --up \
  --down
