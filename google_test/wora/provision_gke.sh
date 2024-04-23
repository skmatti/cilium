#!/bin/bash

set -euxo pipefail
shopt -s inherit_errexit

CILIUM_GITREF="${CILIUM_GITREF?variable must be set, even when set to empty.}"

# Extract the pluginSpecYaml from the rookery config file.
function extract_plugin_spec_yaml {
  local config="${1:?}"
  local plugin_spec_yaml="${2:?}"
  yq '.spec.knests.[].spec.clusters.[].spec.provisionerArgs.pluginSpecYaml' "${config}" >"${plugin_spec_yaml}"
}

# Generate a unique suffix to add to the cluster name.
function cluster_name_suffix {
  local suffix
  suffix="$(tr -dc a-z0-9 < /dev/urandom | head -c 16 || true)"
  if (( ${#suffix} != 16 )); then
    return 1
  fi
  echo "${suffix}"
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
    | select(.component == \"${component}\")
    | .version) = \"${version}\"" "${config}"
}

# Insert the desired component image location.
function insert_component_image {
  local config="${1:?}"
  local component="${2:?}"
  local image="${3:?}"
  yq -i "(.componentOverrides[]
    | select(.component == \"${component}\")
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

if [[ -n "${CILIUM_GITREF}" ]]; then
  insert_component_version "${plugin_spec_yaml}" advanceddatapath "${ADVANCEDDATAPATH_IMAGE_TAG:?}"
  insert_component_image "${plugin_spec_yaml}" advanceddatapath "${ADVANCEDDATAPATH_IMAGE_FULL_NAME:?}"
fi

insert_plugin_spec_yaml "${TBCONFIG}" "${plugin_spec_yaml}"
