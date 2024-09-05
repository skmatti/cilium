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

# Insert the cluster name.
function insert_cluster_name {
  echo 'INFO: insert the cluster name to the cluster Rookery file.' >&2
  local tbconfig_path="${1:?}"
  cluster_name=${PROW_JOB_ID:?}-cluster
  export cluster_name
  yq -i '.spec.knests.[0].spec.clusters.[0].spec.provisionerArgs.clusterName = env(cluster_name)' "${tbconfig_path}"
}

function insert_update_image_map {
  local tbconfig_path="${1:?}"
  local image_registry="${2:?}"
  local cilium_docker_image_tag="${3:?}"
  local operator_docker_image_tag="${4:?}"
  local spec_template="${5:?}"

  export CILIUM_IMAGE=${image_registry}/cilium/cilium:${cilium_docker_image_tag}
  export OPERATOR_IMAGE=${image_registry}/cilium/operator-generic:${operator_docker_image_tag}

  # Replace placeholders with actual values
  spec=$(envsubst '${CILIUM_IMAGE},${OPERATOR_IMAGE}' <${spec_template})
  # format spec to play nice with parsing
  export UPDATE_SPEC_STRING
  UPDATE_SPEC_STRING=$(echo ${spec} | jq -c '.' | sed 's/"/\\"/g')
  updated_tbconfig=$(envsubst '${UPDATE_SPEC_STRING}' <"${tbconfig_path}")
  echo "${updated_tbconfig}" > ${tbconfig_path}
}

# only build and push images if CILIUM_GITREF, IMAGE_REGISTRY, DOCKER_IMAGE_TAG and CILIUM_DOCKER_IMAGE_TAG are set
if [[ -z "${CILIUM_GITREF}" ]]; then
  echo "CILIUM_GITREF is empty, skipping Cilium build." >&2
  export UPDATE_SPEC_STRING=""
  updated_tbconfig=$(envsubst '${UPDATE_SPEC_STRING}' <"${ABSOLUTE_PATH_TBCONFIG}")
  echo "${updated_tbconfig}" > ${ABSOLUTE_PATH_TBCONFIG}
  exit 0
fi

insert_cluster_name "${ABSOLUTE_PATH_TBCONFIG}"

UPDATE_SPEC_TEMPLATE="${WORKDIR}/cilium_update_spec.json.tmpl"

insert_update_image_map "${ABSOLUTE_PATH_TBCONFIG}" "${IMAGE_REGISTRY}" "${CILIUM_DOCKER_IMAGE_TAG}" "${DOCKER_IMAGE_TAG}" "${UPDATE_SPEC_TEMPLATE}"
