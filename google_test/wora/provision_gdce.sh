#!/bin/bash

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

# Add the remoteAddOnBundle field for the gdce-gke cluster Rookery(TBCONFIG).
function insert_addon_config_gcs_location_gdce {
  local tbconfig_path="${1:?}"
  local addon_config_name="${2:?}"
  local addon_config_bucket_url="${3:?}"

  echo 'INFO: insert addon config gcs location to the gdce-gke cluster Rookery file.' >&2
  gdce_plugin_template="${WORKDIR}/gdce_plugin_template.yaml"
  gcs_bucket=$(echo "${addon_config_bucket_url#"gs://"}" | cut -d "/" -f 1)
  gcs_file_location=$(echo "${addon_config_bucket_url#"gs://"}" | cut -d "/" -f 2)/${addon_config_name}

  export gcs_bucket
  export gcs_file_location
  yq -i '
  .cluster.addon.gcsBucket = strenv(gcs_bucket) |
  .cluster.addon.gcsFileLocation = strenv(gcs_file_location)
  ' "${gdce_plugin_template}"

  plugin_content=$(cat "${gdce_plugin_template}")
  export plugin_content
  yq -i '.spec.knests.[0].spec.clusters.[0].spec.provisionerArgs.pluginSpecYaml = strenv(plugin_content)' "${tbconfig_path}"
  # Adjust the yaml multiline string block scalar.
  sed -i -e 's/|-/|/g' "${tbconfig_path}"
}

insert_addon_config_gcs_location_gdce "${ABSOLUTE_PATH_TBCONFIG}" "${ADDON_CONFIG_NAME}" "${ADDON_CONFIG_BUCKET_URL}"

BMCTL_VERSION="0.0.0" \
  ADDON_CONFIG_NAME=${ADDON_CONFIG_NAME} \
  ADDON_CONFIG_BUCKET_URL=${ADDON_CONFIG_BUCKET_URL} \
  IMAGE_REGISTRY=${IMAGE_REGISTRY} \
  DOCKER_IMAGE_TAG=${DOCKER_IMAGE_TAG} \
  CILIUM_DOCKER_IMAGE_TAG=${CILIUM_DOCKER_IMAGE_TAG} \
  CREATE_NAMESPACE=${create_namspace:-false} \
  CREATE_GCR_SECRET=${CREATE_GCR_SECRET:-true} \
  PATCH_CONTENT_DIR=${PATCH_CONTENT_DIR} \
  WORKDIR="${WORKDIR}" \
  "${ROOT}"/provision.sh
