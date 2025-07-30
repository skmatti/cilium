#!/bin/bash
#
set -ex

ROOT="$(dirname -- "${BASH_SOURCE[0]}")"
WORKDIR="${WORKDIR:-${ROOT}}"
ABSOLUTE_PATH_TBCONFIG=${ABSOLUTE_PATH_TBCONFIG-}
ADD_SUFFIX="${ADD_SUFFIX:-false}"
RUN_ID="${RUN_ID:?}"
GENERATE_ADDON_ONLY="${GENERATE_ADDON_ONLY:-false}"

ADDON_CONFIG_URL=${ADDON_CONFIG_URL:?}
CILIUM_GITREF="${CILIUM_GITREF?variable must be set, even when set to empty.}"
CILIUM_IMAGE_REF="${CILIUM_IMAGE_REF:?}"
OPERATOR_IMAGE_REF="${OPERATOR_IMAGE_REF:?}"
PATCH_CONTENT_DIR="${PATCH_CONTENT_DIR:?}"
CLUSTER_ID="${CLUSTER_ID:?}"

# Insert the cluster name.
function insert_cluster_name {
  echo 'INFO: insert the cluster name to the cluster Rookery file.' >&2
  local tbconfig_path="${1:?}"
  local cluster_name="${2:?}"
  local cluster_idx="${3:?}"
  env cluster_name="${cluster_name}" \
  yq -i ".spec.knests.[0].spec.clusters.[$((cluster_idx))].spec.provisionerArgs.clusterName = env(cluster_name)" "${tbconfig_path}"
}

# Add the remoteAddOnBundle field for the baremetal-gke cluster Rookery(TBCONFIG).
function insert_addon_config_gcs_location_abm {
  local tbconfig_path="${1:?}"
  local addon_config_url="${2:?}"
  local cluster_idx="${3:?}"
  echo 'INFO: insert addon config gcs location to the baremetal-gke cluster Rookery file.' >&2
  env addon_config_url="${addon_config_url}" \
  yq -i ".spec.knests.[0].spec.clusters.[$((cluster_idx))].spec.provisionerArgs.remoteAddOnBundle = strenv(addon_config_url)" "${tbconfig_path}"
}

if [[ -z "${CILIUM_GITREF}" ]]; then
  echo "CILIUM_GITREF is empty, skipping Cilium build." >&2
  exit 0
fi

cluster_name="${RUN_ID}-cluster"
cluster_ns="cluster-${RUN_ID}-cluster"
if [[ "${ADD_SUFFIX}" = "true" ]]; then
  cluster_name+="-${CLUSTER_ID}"
  cluster_ns+="-${CLUSTER_ID}"
fi
cluster_idx="$((CLUSTER_ID-1))"

if [[ "${GENERATE_ADDON_ONLY}" != "true" ]]; then
  insert_cluster_name "${ABSOLUTE_PATH_TBCONFIG}" "${cluster_name}" "${cluster_idx}"
  insert_addon_config_gcs_location_abm "${ABSOLUTE_PATH_TBCONFIG}" "${ADDON_CONFIG_URL}" "${cluster_idx}"
fi

BMCTL_VERSION=$(yq ".spec.knests.[0].spec.clusters.[${cluster_idx}].spec.provisionerArgs.bmctlVersion" "${ABSOLUTE_PATH_TBCONFIG}")

env \
  BMCTL_VERSION="${BMCTL_VERSION}" \
  ADDON_CONFIG_URL=${ADDON_CONFIG_URL} \
  OPERATOR_IMAGE_REF=${OPERATOR_IMAGE_REF} \
  CILIUM_IMAGE_REF=${CILIUM_IMAGE_REF} \
  CREATE_NAMESPACE=${CREATE_NAMESPACE:-true} \
  CLUSTER_NAMESPACE="${cluster_ns}" \
  CLUSTER_ID="${CLUSTER_ID}" \
  CREATE_GCR_SECRET="${CREATE_GCR_SECRET:-false}" \
  PATCH_CONTENT_DIR=${PATCH_CONTENT_DIR} \
  WORKDIR="${WORKDIR}" \
  RUN_ID="${RUN_ID}" \
  "${ROOT}"/provision.sh
