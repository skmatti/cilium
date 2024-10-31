#!/bin/bash
#
set -ex

ROOT="$(dirname -- "${BASH_SOURCE[0]}")"
WORKDIR="${WORKDIR:-${ROOT}}"
ABSOLUTE_PATH_TBCONFIG=${ABSOLUTE_PATH_TBCONFIG-}
IMAGE_REGISTRY="${IMAGE_REGISTRY:-}"
DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG:-}"
CILIUM_DOCKER_IMAGE_TAG="${CILIUM_DOCKER_IMAGE_TAG:-}"
CILIUM_GITREF="${CILIUM_GITREF?variable must be set, even when set to empty.}"
OC_UPDATE_TEMPLATE="${OC_UPDATE_TEMPLATE:-}"
ENV_TEMPLATE_ID="${ENV_TEMPLATE_ID:-}"
GDCH_E2E_TESTS="${GDCH_E2E_TESTS:-}"
GDCH_E2E_TEST_PLAN="${GDCH_E2E_TEST_PLAN:-}"
ADHOC_USERNAME="${ADHOC_USERNAME:-}"

# Insert the cluster name.
function insert_cluster_name {
  echo 'INFO: insert the cluster name to the cluster Rookery file.' >&2
  local tbconfig_path="${1:?}"
  cluster_name=${PROW_JOB_ID:?}-cluster
  export cluster_name
  yq -i '.spec.knests.[0].spec.clusters.[0].spec.provisionerArgs.clusterName = env(cluster_name)' "${tbconfig_path}"
}

function retag_docker_image {
  local docker_image="${1:?}"
  local old_tag="${2:?}"
  local new_tag="${3:?}"
  docker tag "${docker_image}:${old_tag}" "${docker_image}:${new_tag}"
  docker push "${docker_image}:${new_tag}"
}

function insert_update_image_map {
  local tbconfig_path="${1:?}"
  local image_registry="${2:?}"
  local docker_image_tag="${3:?}"
  local spec_template="${4:?}"

  export CILIUM_IMAGE=${image_registry}/cilium/cilium:${docker_image_tag}
  export OPERATOR_IMAGE=${image_registry}/cilium/operator-generic:${docker_image_tag}

  # Replace placeholders with actual values
  spec=$(envsubst '${CILIUM_IMAGE},${OPERATOR_IMAGE}' <${spec_template})
  # format spec to play nice with parsing
  export UPDATE_SPEC_STRING
  UPDATE_SPEC_STRING=$(echo ${spec} | jq -c '.' | sed 's/"/\\"/g')
  updated_tbconfig=$(envsubst '${UPDATE_SPEC_STRING}' <"${tbconfig_path}")
  echo "${updated_tbconfig}" >${tbconfig_path}
}

function insert_env_template_id {
  local tbconfig_path="${1:?}"
  export ENV_TEMPLATE_ID="${2:?}"
  updated_tbconfig=$(envsubst '${ENV_TEMPLATE_ID}' <"${tbconfig_path}")
  echo "${updated_tbconfig}" >${tbconfig_path}
}

function insert_adhoc_username {
  local tbconfig_path="${1:?}"
  export ADHOC_USERNAME="${2:?}"
  updated_tbconfig=$(envsubst '${ADHOC_USERNAME}' <"${tbconfig_path}")
  echo "${updated_tbconfig}" >${tbconfig_path}
}

function insert_gdch_e2e_tests {
  local tbconfig_path="${1:?}"
  export GDCH_E2E_TESTS="${2:-}"
  export GDCH_E2E_TEST_PLAN="${3:-}"
  updated_tbconfig=$(envsubst '${GDCH_E2E_TESTS},${GDCH_E2E_TEST_PLAN}' <"${tbconfig_path}")
  echo "${updated_tbconfig}" >${tbconfig_path}
}

insert_adhoc_username "${ABSOLUTE_PATH_TBCONFIG}" "${ADHOC_USERNAME}"
insert_cluster_name "${ABSOLUTE_PATH_TBCONFIG}"
insert_env_template_id "${ABSOLUTE_PATH_TBCONFIG}" "${ENV_TEMPLATE_ID}"
insert_gdch_e2e_tests "${ABSOLUTE_PATH_TBCONFIG}" "${GDCH_E2E_TESTS}" "${GDCH_E2E_TEST_PLAN}"

# only build and push images if CILIUM_GITREF, IMAGE_REGISTRY, DOCKER_IMAGE_TAG and CILIUM_DOCKER_IMAGE_TAG are set
if [[ -z "${CILIUM_GITREF}" ]]; then
  echo "CILIUM_GITREF is empty, skipping Cilium build." >&2
  export UPDATE_SPEC_STRING=""
  updated_tbconfig=$(envsubst '${UPDATE_SPEC_STRING}' <"${ABSOLUTE_PATH_TBCONFIG}")
  echo "${updated_tbconfig}" >${ABSOLUTE_PATH_TBCONFIG}
  exit 0
fi

# GDCH OCLCM relies on images having the same docker tag
TAG="an-shift-left-${DOCKER_IMAGE_TAG}"
retag_docker_image "${IMAGE_REGISTRY}/cilium/cilium" "${CILIUM_DOCKER_IMAGE_TAG}" "${TAG}"
retag_docker_image "${IMAGE_REGISTRY}/cilium/operator-generic" "${DOCKER_IMAGE_TAG}" "${TAG}"

insert_update_image_map "${ABSOLUTE_PATH_TBCONFIG}" "${IMAGE_REGISTRY}" "${TAG}" "${WORKDIR}/${OC_UPDATE_TEMPLATE}"
