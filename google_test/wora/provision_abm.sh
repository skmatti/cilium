#!/bin/bash
#
set -ex

ROOT="$(dirname -- "${BASH_SOURCE[0]}")"
WORKDIR="${WORKDIR:-${ROOT}}"
ABSOLUTE_PATH_TBCONFIG=${ABSOLUTE_PATH_TBCONFIG-}
ADDON_CONFIG_NAME=${ADDON_CONFIG_NAME:-}
ADDON_CONFIG_BUCKET_URL=${ADDON_CONFIG_BUCKET_URL:-}
IMAGE_REGISTRY="${IMAGE_REGISTRY:-}"
DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG:-}"
CILIUM_DOCKER_IMAGE_TAG="${CILIUM_DOCKER_IMAGE_TAG:-}"
PATCH_CONTENT_DIR=${PATCH_CONTENT_DIR:-${ROOT}/addon/patch_content/abm-1.28.0-gke.311/image-only-templates}
CILIUM_GITREF="${CILIUM_GITREF?variable must be set, even when set to empty.}"

# Insert the cluster name.
function insert_cluster_name {
  echo 'INFO: insert the cluster name to the cluster Rookery file.' >&2
  local tbconfig_path="${1:?}"
  cluster_name=${PROW_JOB_ID:?}-cluster
  export cluster_name
  yq -i '.spec.knests.[0].spec.clusters.[0].spec.provisionerArgs.clusterName = env(cluster_name)' "${tbconfig_path}"
}

# Add the remoteAddOnBundle field for the baremetal-gke cluster Rookery(TBCONFIG).
function insert_addon_config_gcs_location_abm {
  local tbconfig_path="${1:?}"
  local addon_config_name="${2:?}"
  local addon_config_bucket_url="${3:?}"
  local addon_config_url="${addon_config_bucket_url}/${addon_config_name}"
  echo 'INFO: insert addon config gcs location to the baremetal-gke cluster Rookery file.' >&2
  export addon_config_url
  yq -i '.spec.knests.[0].spec.clusters.[0].spec.provisionerArgs.remoteAddOnBundle = strenv(addon_config_url)' "${tbconfig_path}"
}

if [[ -z "${CILIUM_GITREF}" ]]; then
  echo "CILIUM_GITREF is empty, skipping Cilium build." >&2
  exit 0
fi

insert_cluster_name "${ABSOLUTE_PATH_TBCONFIG}"
insert_addon_config_gcs_location_abm "${ABSOLUTE_PATH_TBCONFIG}" "${ADDON_CONFIG_NAME}" "${ADDON_CONFIG_BUCKET_URL}"

BMCTL_VERSION=$(yq ".spec.knests.[0].spec.clusters[0].spec.provisionerArgs.bmctlVersion" "${ABSOLUTE_PATH_TBCONFIG}") \
ADDON_CONFIG_NAME=${ADDON_CONFIG_NAME} \
ADDON_CONFIG_BUCKET_URL=${ADDON_CONFIG_BUCKET_URL} \
IMAGE_REGISTRY=${IMAGE_REGISTRY} \
DOCKER_IMAGE_TAG=${DOCKER_IMAGE_TAG} \
CILIUM_DOCKER_IMAGE_TAG=${CILIUM_DOCKER_IMAGE_TAG} \
CREATE_NAMESPACE=${create_namspace:-true} \
CREATE_GCR_SECRET="${CREATE_GCR_SECRET:-false}" \
PATCH_CONTENT_DIR=${PATCH_CONTENT_DIR} \
WORKDIR="${WORKDIR}" \
  "${ROOT}"/provision.sh
