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

# shellcheck disable=SC1091
source "$(dirname -- "${BASH_SOURCE[0]}")"/remote_execution.sh

# Derive semi-unique id for rookery containing test application.
TEST_RUN_ID=${KUBETEST2_RUN_ID:-unset-id}

# Revert KUBECONFIG change made by kt2-tb, to avoid control plane login to mess
# up SUT cluster's kubeconfig.
if [[ -n "${OLD_KUBECONFIG}" ]] && [[ -n "${ARTIFACTS}" ]] && [[ "${KUBECONFIG#"${ARTIFACTS}"}" != "${KUBECONFIG}" ]]; then
  export KUBECONFIG="${OLD_KUBECONFIG-}"
fi

function calculate_cluster_artifacts() {
  local -r config="${1:?}"
  local -r artifacts="${2:?}"
  local -a cluster_artifacts_subdirs=()
  local -a resolved_cluster_artifacts_subdirs=()
  # Find paths of cluster artifacts subdirectories.
  mapfile -t cluster_artifacts_subdirs < <(
    # shellcheck disable=SC2016
    yq '.spec.knests[] as $knest
    | $knest.spec.clusters[] as $cluster
    | ".tailorbird/artifacts"
    + "/knests/\($knest.metadata.name)"
    + "/clusters/\($cluster.metadata.name)"' "${config}" || true
  )
  if [[ "${#cluster_artifacts_subdirs[@]}" -eq 0 ]]; then
    echo "No clusters found in ${config}" >&2
    return 1
  fi
  # Resolve links to find absolute paths.
  for cluster_artifacts_subdir in "${cluster_artifacts_subdirs[@]}"; do
    local resolved_path
    # Check for empty knest or cluster names.
    if [[ "${cluster_artifacts_subdir}" == *//* ]]; then
      echo "Invalid cluster artifacts subdirectory: ${cluster_artifacts_subdir}" >&2
      return 1
    fi
    resolved_path=$(realpath "${artifacts}/${cluster_artifacts_subdir}")
    resolved_cluster_artifacts_subdirs+=("${resolved_path}")
  done
  printf "%s," "${resolved_cluster_artifacts_subdirs[@]}" | sed 's/,$//'
}

function calculate_cluster_refs() {
  local paths="${1:?}"
  local -a path_array=()
  local output=""
  local i=1
  # Split the input string into an array
  IFS=',' read -ra path_array <<<"${paths}"

  # Check if there is only one path
  if [[ "${#path_array[@]}" -eq 1 ]]; then
    output="oob=${path_array[0]}"
  else
    # Loop through each path and construct the output
    for path in "${path_array[@]}"; do
      output+=",oob${i}=${path}"
      i=$((i + 1))
    done
    # Remove the first comma
    output="${output:1}"
  fi
  echo "${output}"
}

CLUSTER_ARTIFACTS=$(calculate_cluster_artifacts "${TBCONFIG:?}" "${ARTIFACTS}")
CLUSTER_REFS=$(calculate_cluster_refs "${CLUSTER_ARTIFACTS}")

# Folder for nested WORA runs, to make file layout more clear.
WORA_ARTIFACTS="${ARTIFACTS}/wora"
ARTIFACTS_BASE="${ARTIFACTS}"
CLASS_NAME_PREFIX=""
if [[ "${IS_MULTISTAGE:-false}" == "true" ]]; then
  WORA_ARTIFACTS="${ARTIFACTS}/wora/phase1"
  CLASS_NAME_PREFIX="Phase 1: "
fi

function unsetResourceVars() {
  unset HTTP_PROXY
  unset HTTPS_PROXY
  unset KUBECONFIG
}

# unset proxy environment variables, so it wouldn't mess up with gcloud
# interactions.
unsetResourceVars

# Upload-external-clusters name should match namePrefix in WORA yaml. Because
# test is going to have its own junit.xml, suppress kt2 junit generation.
# Status-check-interval is increased to work around incorrect calculation of
# rookery status.
ARTIFACTS_BASE="${ARTIFACTS_BASE}" \
ARTIFACTS="${WORA_ARTIFACTS}" \
  kubetest2-tailorbird \
  --verbose \
  --run-id="${TEST_RUN_ID}" \
  --tbenv="${TBENV:?}" \
  --tbconfig="${WORA_CONFIG:?}" \
  --upload-external-clusters="${CLUSTER_REFS}" \
  --client-polling-interval=90s \
  --up \
  --down

function check_junit_files_for_errors() {
  local junit_files
  local junit_file
  local test_suites
  local test_suite
  local total_errors=0
  local total_failures=0
  mapfile -t junit_files < <(find "${WORA_ARTIFACTS}" -name junit_\*.xml)
  for junit_file in "${junit_files[@]}"; do
    # Add prefix to the classname to distinguish between tests run in multiple phases in prow page.
    if [[ -n "${CLASS_NAME_PREFIX}" ]]; then
      sed -E -i 's/(classname=")([^"]*)(")/\1'"${CLASS_NAME_PREFIX}"'\2\3/' "${junit_file}"
    fi
    echo "Checking ${junit_file} for failures"
    readarray -t test_suites < <(grep -E '(<testsuite).*>' "${junit_file}" || true)
    for test_suite in "${test_suites[@]}"; do
      errors="$(echo "${test_suite}" | sed -n 's/.*errors="\([0-9]*\)".*/\1/p')"
      failures="$(echo "${test_suite}" | sed -n 's/.*failures="\([0-9]*\)".*/\1/p')"
      if ((${errors:-0} != 0)) || ((${failures:-0} != 0)); then
        total_errors=$((total_errors+errors))
        total_failures=$((total_failures+failures))
        echo "Failures found in produced ${junit_file} output." >&2
      fi
    done
  done
  if ((${total_errors:-0} != 0)) || ((${total_failures:-0} != 0)); then
    echo "Errors(${total_errors}) or failures(${total_failures}) found in produced output. Failing workflow" >&2
    return 1
  fi
}

check_junit_files_for_errors

if [[ "${IS_MULTISTAGE:-false}" != "true" ]]; then
  exit 0
fi

echo "INFO: Multistage testing requested, updating cluster to desired Cilium version."

unsetResourceVars

ARTIFACTS_BASE="${ARTIFACTS_BASE}" \
TARGET_ADDON_CONFIG="${MULTISTAGE_ADDON_CONFIG_GSPATH:-}" \
"$(dirname -- "${BASH_SOURCE[0]}")"/multistage/infra.sh
WORA_ARTIFACTS="${ARTIFACTS}/wora/phase2"

echo "INFO: Cilium updated, running tests again."
ARTIFACTS_BASE="${ARTIFACTS_BASE}" \
ARTIFACTS="${WORA_ARTIFACTS}" \
  kubetest2-tailorbird \
  --verbose \
  --run-id="${TEST_RUN_ID}" \
  --tbenv="${TBENV:?}" \
  --tbconfig="${WORA_CONFIG:?}" \
  --upload-external-clusters="${CLUSTER_REFS}" \
  --client-polling-interval=90s \
  --up \
  --down

CLASS_NAME_PREFIX="Phase 2: "
check_junit_files_for_errors
