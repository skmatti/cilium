#!/bin/bash

set -euxo pipefail
shopt -s inherit_errexit

echo
echo "==============================================================================="
echo "Starting WORA test execution"

function log_finish() {
  if [[ -n "${WORA_ARTIFACTS:-}" ]] && [[ -n "${TEST_RUN_ID:-}" ]]; then
    rm -f "${WORA_ARTIFACTS}/${TEST_RUN_ID}/junit_runner.xml"
  fi
  set +o xtrace
  echo "==============================================================================="
  echo "End of WORA test execution"
  echo
}
trap log_finish exit

set -x

# Derive semi-unique id for rookery containing test application.
TEST_RUN_ID=${KUBETEST2_RUN_ID:-unset-id}-${BASHPID:?}

# Revert KUBECONFIG change made by kt2-tb, to avoid control plane login to mess
# up SUT cluster's kubeconfig.
if [[ -n "${ARTIFACTS}" ]] && [[ "${KUBECONFIG#"${ARTIFACTS}"}" != "${KUBECONFIG}" ]]; then
  export KUBECONFIG="${OLD_KUBECONFIG-}"
fi

# This is used to set the cluster artifacts env var.
CLUSTER_ARTIFACTS_SUBDIR="$(yq '".tailorbird/artifacts/knests/" + (.spec.knests[0].spec.clusters[0].metadata.name // "null") + "/clusters/" + (.spec.knests[0].spec.clusters[0].metadata.name // "null")' "${TBCONFIG:?}")"

# Resolve symlink to work around OOB artifact packaging bug. Symlink value
# should point to a cluster's artifact folder against which test will run.
CLUSTER_ARTIFACTS=$(realpath "${ARTIFACTS}/${CLUSTER_ARTIFACTS_SUBDIR}")

# Folder for nested WORA runs, to make file layout more clear.
WORA_ARTIFACTS="${ARTIFACTS}/wora"

# Upload-external-clusters name should match namePrefix in WORA yaml. Because
# test is going to have its own junit.xml, suppress kt2 junit generation.
# Status-check-interval is increased to work around incorrect calculation of
# rookery status.
ARTIFACTS="${WORA_ARTIFACTS}" \
  kubetest2-tailorbird \
  --verbose \
  --run-id "${TEST_RUN_ID}" \
  --tbenv="${TBENV:?}" \
  --tbconfig "${WORA_CONFIG:?}" \
  --upload-external-clusters "oob=${CLUSTER_ARTIFACTS}" \
  --status-check-interval=90 \
  --up \
  --down

mapfile -t junit_files < <(find "${WORA_ARTIFACTS}" -name junit_\*.xml)
for junit_file in "${junit_files[@]}"; do
  echo "Checking ${junit_file} for failures"
  line="$(grep -E '(<testsuites).*>' "${junit_file}")"
  errors="$(sed -e 's/.*errors="//' -e 's/".*//' <(echo "${line}"))"
  failures="$(sed -e 's/.*failures="//' -e 's/".*//' <(echo "${line}"))"
  if ((${errors:-0} != 0)) || ((${failures:-0} != 0)); then
    echo "Failures found in produced ${junit_file} output. Failing workflow" >&2
    exit 1
  fi
done
