#!/bin/bash
#
# Reproduce a cluster environment by passing the failed jobname and looking
# for configuration in the prow job.
# This script sets RUN_DOWN=false
# and exports all other env vars from the job definition.
# Passing RUN_ID can help accelerate the cluster to be ready if the resources still exist

# --- Configuration ---
WORA_DIR="$(dirname -- "${BASH_SOURCE[0]}")"
PROW_DIR="$(realpath --relative-to=. "${WORA_DIR}/../../.prow")"
ENTRYPOINT_SCRIPT="${WORA_DIR}/prow_entrypoint.sh"

# --- Variables ---
JOB_NAME=""
RUN_ID=""
ENV_VARS_TO_EXPORT=()

# --- Functions ---
log() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] $*"
}

usage() {
  echo "Usage: $0 --job-name <JOB_NAME> [OPTIONS]"
  echo "  Sets up a WORA debug environment by running ${ENTRYPOINT_SCRIPT}"
  echo "  with RUN_DOWN=false, an extended TTL, and all env vars from the job spec."
  echo
  echo "Required arguments:"
  echo "  --job-name <JOB_NAME>     The name of the Prow job as defined in the YAML."
  echo
  echo "Optional arguments:"
  echo "  --run-id <RUN_ID>         The RUN_ID to use. If not provided, defaults to ${USER}."
  echo "  -h|--help                Show this help message."
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --job-name)
      JOB_NAME="$2"
      shift 2
      ;;
    --run-id)
      RUN_ID="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log "ERROR: Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

# --- Validate required arguments ---
if [[ -z "${JOB_NAME}" ]]; then
  log "ERROR: --job-name is required."
  usage
  exit 1
fi

# --- Set default RUN_ID if not provided ---
if [[ -z "${RUN_ID}" ]]; then
  RUN_ID="${USER}"
  log "RUN_ID not provided, using default: ${RUN_ID}"
else
  log "Using provided RUN_ID: ${RUN_ID}"
fi
ENV_VARS_TO_EXPORT+=("RUN_ID=${RUN_ID}")
ENV_VARS_TO_EXPORT+=("RUN_DOWN=false")

# --- Main Script ---
log "Setting up debug environment for JOB: ${JOB_NAME}"

# 1. Find the job and extract all environment variables
log "Searching for job '${JOB_NAME}' and its env vars in YAML files under ${PROW_DIR}..."

declare -a JOB_ENVS
mapfile -t JOB_ENVS < <(yq e '.. | select(.name? == "'"${JOB_NAME}"'") | .spec.containers[0].env[] | .name + "=" + .value' ${PROW_DIR}/*.yaml 2>/dev/null)

if (( ${#JOB_ENVS[@]} == 0 )); then
  log "ERROR: Failed to find job ${JOB_NAME} or its env vars in any YAML file in ${PROW_DIR}."
  log "Please check the job name, the YAML structures, and that files exist matching ${PROW_DIR}/*.yaml"
  exit 1
fi

log "Found environment variables for job ${JOB_NAME}:"
printf "  %s\n" "${JOB_ENVS[@]}"

EXPORTED_ENV_VARS+=("${JOB_ENVS[@]}")
TBCONFIG_VALUE=""

for JOB_ENV in "${JOB_ENVS[@]}"; do
  if [[ "${JOB_ENV%%=*}" == "TBCONFIG" ]]; then
    TBCONFIG_VALUE="${JOB_ENV#*=}"
    break
  fi
done

if [[ -z "${TBCONFIG_VALUE}" ]]; then
  log "ERROR: TBCONFIG environment variable not found in the job spec for ${JOB_NAME}."
  exit 1
fi

# 3. Execute the entrypoint script
log "Executing command with the following environment:"
for VAR in "${ENV_VARS_TO_EXPORT[@]}"; do
  log "  ${VAR}"
done
echo "--------------------------------------------------"

# Export variables and run the script
env "${ENV_VARS_TO_EXPORT[@]}" "${ENTRYPOINT_SCRIPT}"
EXEC_RVAL=$?
echo "--------------------------------------------------"

if [[ ${EXEC_RVAL} -eq 0 ]]; then
  log "SUCCESS: Entrypoint script finished."
  log "RUN_ID used: ${RUN_ID}"
  log "TBCONFIG: ${TBCONFIG_VALUE}"
else
  log "ERROR: Entrypoint script failed with exit code ${EXEC_RVAL}."
  exit ${EXEC_RVAL}
fi

log "Reproduced the cluster environment successfully."
