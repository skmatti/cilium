#!/bin/bash

set -euxo pipefail
shopt -s inherit_errexit

# Extract the pluginSpecYaml from the rookery config file.
function extract_plugin_spec_yaml {
  local config="${1:?}"
  local plugin_spec_yaml="${2:?}"
  yq '.spec.knests.[0].spec.clusters.[0].spec.provisionerArgs.pluginSpecYaml' "${config}" > "${plugin_spec_yaml}"
}

# Generate a unique suffix to add to the cluster name.
function cluster_name_suffix {
    local suffix
    suffix="$(uuidgen | tr -d '-')"
    echo "${suffix::16}"
}

# Insert a suffix into the cluster name.
function insert_cluster_name_suffix {
  local config="${1:?}"
  local suffix="${2:?}"
  yq -i ".clusterOptions.clusters += \"-${suffix}\"" "${config}"
}

# Insert the desired component version.
function insert_component_version {
  local config="${1:?}"
  local component="${2:?}"
  local version="${3:?}"
  yq -i "(.componentOverrides[]
    | select( .component == \"${component}\" )
    | .version) = \"${version}\"" "${config}"
}

# Insert the desired component image location.
function insert_component_image {
  local config="${1:?}"
  local component="${2:?}"
  local image="${3:?}"
  yq -i "(.componentOverrides[]
    | select( .component == \"${component}\" )
    | .testOnlyComponentImage) = \"${image}\"" "${config}"
}

# Insert pluginSpecYaml into the rookery config file.
function insert_plugin_spec_yaml {
  local config="${1:?}"
  local plugin_spec_yaml="${2:?}"
  local output
  output="$(sed 's|"|\\"|g' "${plugin_spec_yaml}")"
  yq -i ".spec.knests.[].spec.clusters.[].spec.provisionerArgs.pluginSpecYaml = \"${output}\n\"" "${config}"
}

plugin_spec_yaml="$(mktemp -t plugin_spec_yaml.XXXXXXXXXX)"
trap 'rm -rf "${plugin_spec_yaml}"' EXIT

suffix="$(cluster_name_suffix)"

extract_plugin_spec_yaml "${TBCONFIG:?}" "${plugin_spec_yaml}"
insert_cluster_name_suffix "${plugin_spec_yaml}" "${suffix}"
insert_component_version "${plugin_spec_yaml}" advanceddatapath "${ADVANCEDDATAPATH_IMAGE_TAG:?}"
insert_component_image "${plugin_spec_yaml}" advanceddatapath "${ADVANCEDDATAPATH_IMAGE_FULL_NAME:?}"

insert_plugin_spec_yaml "${TBCONFIG}" "${plugin_spec_yaml}"
