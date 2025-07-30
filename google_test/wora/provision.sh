#!/bin/bash
# This script will be called by prow_entrypoint.sh to create an
# AddOnConfiguration yaml file and upload it to a given gcs bucket destination.

set -ex
SCRIPT_DIR=$(dirname -- "${BASH_SOURCE[0]}")
WORKDIR=${WORKDIR:-${SCRIPT_DIR}}
GENERATED_CONFIGS_DIR="${GENERATED_CONFIGS_DIR:-"${WORKDIR}/generated_configs"}"

if [[ -z ${RUN_ID:-} ]]; then
  echo "ERROR: must specify RUN_ID." >&2
  exit 1
fi

if [[ -z ${CREATE_NAMESPACE:-} ]]; then
  echo "ERROR: must specify CREATE_NAMESPACE." >&2
  exit 1
fi

if [[ -z ${CLUSTER_NAMESPACE:-} ]]; then
  echo "ERROR: must specify CLUSTER_NAMESPACE." >&2
  exit 1
fi

if [[ -z ${CLUSTER_ID:-} ]]; then
  echo "ERROR: must specify CLUSTER_ID." >&2
  exit 1
fi

if [[ -z ${CREATE_GCR_SECRET:-} ]]; then
  echo "ERROR: must specify CREATE_GCR_SECRET." >&2
  exit 1
fi

if [[ -z ${BMCTL_VERSION:-} ]]; then
  echo "ERROR: must specify BMCTL_VERSION, the exact full version of anthos cluster, example 1.14.3." >&2
  exit 1
fi

if [[ -z ${ADDON_CONFIG_URL:-} ]]; then
  echo "ERROR: must specify ADDON_CONFIG_URL, the path to GCS file where the Tailorbird can access the addon Configuration." >&2
  exit 1
fi

if [[ -z ${CILIUM_IMAGE_REF:-} ]]; then
  echo "ERROR: must specify CILIUM_IMAGE_REF, reference for cilium image." >&2
  exit 1
fi

if [[ -z ${OPERATOR_IMAGE_REF:-} ]]; then
  echo "ERROR: must specify OPERATOR_IMAGE_REF, reference for cilium operator image." >&2
  exit 1
fi

if [[ -z ${PATCH_CONTENT_DIR:-} ]]; then
  echo "ERROR: must specify PATCH_CONTENT_DIR." >&2
  exit 1
fi

echo "RUN_ID                  = ${RUN_ID}"
echo "CREATE_NAMESPACE        = ${CREATE_NAMESPACE}"
echo "CREATE_GCR_SECRET       = ${CREATE_GCR_SECRET}"
echo "BMCTL_VERSION           = ${BMCTL_VERSION}"
echo "ADDON_CONFIG_URL        = ${ADDON_CONFIG_URL}"
echo "CILIUM_IMAGE_REF        = ${CILIUM_IMAGE_REF}"
echo "OPERATOR_IMAGE_REF      = ${OPERATOR_IMAGE_REF}"
echo "WORKDIR                 = ${WORKDIR}"

# Function to update the image for operator.yaml
function update_operator_image {
  local image="${1:?}"
  local tmp_dir="${2:?}"
  generated_operator_yaml=${tmp_dir}/$(find "${tmp_dir}"/ -name '*anet-operator*' | sed "s/.*\///")
  env image="${image}" \
  yq -i '(.spec.template.spec.containers[] | select(.name=="cilium-operator") | .image) = strenv(image)' "${generated_operator_yaml}"
}

# Function to update the image for anet.yaml
function update_cilium_image {
  local image="${1:?}"
  local tmp_dir="${2:?}"
  generated_anet_yaml=${tmp_dir}/$(find "${tmp_dir}"/ -name '*anetd*' | sed "s/.*\///")
  env image="${image}" \
  yq -i '(.spec.template.spec.containers[] | select(.image=="*/cilium/cilium:*") | .image) = strenv(image)
  | (.spec.template.spec.initContainers[] | select(.image=="*/cilium/cilium:*") | .image) = strenv(image)' "${generated_anet_yaml}"
}

# Function to update the cluster name & id in cilium config
function update_cilium_cluster_name_id {
  local cluster_id="${1:?}"
  local tmp_dir="${2:?}"
  generated_configmap_yaml=${tmp_dir}/$(find "${tmp_dir}"/ -name '*cilium-config*' | sed "s/.*\///")

  if yq -e '.data.cluster-id and .data.cluster-name' "${generated_configmap_yaml}" > /dev/null; then
    env \
    cluster_id="${cluster_id}" \
    cluster_name_suffix="-${cluster_id}" \
    yq -i '.data.cluster-id = strenv(cluster_id) | .data.cluster-name += strenv(cluster_name_suffix)' "${generated_configmap_yaml}"
  fi
}

# Function to attach generated secret to the given sa config.
function attach_sa_secret {
  local gcr_secret_name="${1:?}"
  local original_sa_config_path="${2:?}"
  local updated_sa_config_path="${3:?}"

  if [[ "${original_sa_config_path}" != "${updated_sa_config_path}" ]]; then
    cp "${original_sa_config_path}" "${updated_sa_config_path}"
  fi

  env gcr_secret_name="${gcr_secret_name}" \
  yq -i '( .imagePullSecrets += [{"name": strenv(gcr_secret_name)}])' "${updated_sa_config_path}"
}

# Process Addon configuration.
function generate_addon_config {
  local addon_config_path="${1:?}"
  local namespace="${2:?}"
  local patch_content_dir="${3:?}"
  local tmp_dir="${4:?}"
  env namespace="${namespace}" \
  yq '
  .metadata.name = strenv(RUN_ID) |
  .metadata.namespace = strenv(namespace) |
  .spec.anthosBareMetalVersions[0] = env(BMCTL_VERSION)
' "${SCRIPT_DIR}"/addon/configuration.yaml >"${addon_config_path}"

  for file in "${tmp_dir}"/*.yaml; do
    if [[ -f "${file}" ]]; then
      api_version=$(yq '.apiVersion' "${file}")
      export api_version
      kind=$(yq '.kind' "${file}")
      export kind
      name=$(yq '.metadata.name' "${file}")
      export name
      namespace=$(yq '.metadata.namespace' "${file}")
      # Set priority to test-infra range. http://go/abm-component-overrides#patch-priority.
      priority=350
      export priority
      if [[ -n $(yq '.patchType' "${file}") ]] && [[ $(yq '.patchType' "${file}") == "json" ]]; then
        patch_content=$(yq '.patchContent' "${file}")
        export patch_content
        patch_type="json"
        export patch_type
      else
        patch_type="strategic"
        export patch_type
        patch_content=$(cat "${file}")
        export patch_content
      fi
      if [[ "${namespace}" != "null" ]]; then
        export namespace
        yq -i '.spec.configs += {"apiVersion": strenv(api_version), "kind" : strenv(kind), "name" : strenv(name), "namespace": strenv(namespace), "priority": env(priority), "patchType": strenv(patch_type), "patchContent" : strenv(patch_content)}' "${addon_config_path}"
      else
        yq -i '.spec.configs += {"apiVersion": strenv(api_version), "kind" : strenv(kind), "name" : strenv(name), "priority": env(priority), "patchType": strenv(patch_type), "patchContent" : strenv(patch_content)}' "${addon_config_path}"
      fi
    fi
  done
  # Adjust the yaml multiline string block scalar.
  sed -i -e 's/|-/|/g' "${addon_config_path}"
  # Remove the placeholder in the configs.
  sed -i '/placeholder/d' "${addon_config_path}"
}

# Function to generate secret to pull images from private GCR.
function generate_gcr_secret_config {
  local gcr_secret_config_path="${1:?}"
  local gcr_secret_name="${2:?}"
  local service_account=anthos-networking-ci-runner@anthos-networking-ci.iam.gserviceaccount.com

  kubectl create secret docker-registry "${gcr_secret_name}" \
    --namespace=kube-system \
    --docker-server=gcr.io \
    --docker-username=oauth2accesstoken \
    --docker-email="${service_account}" \
    --docker-password="$(gcloud auth print-access-token --impersonate-service-account "${service_account}")" \
    --dry-run=client -o yaml >"${gcr_secret_config_path}"
}

# Function to generate namespace yaml.
function generate_namespace_config {
  local namespace_config_path="${1:?}"
  namespace="${2:?}"
  export namespace
  yq '
  .metadata.name = strenv(namespace) |
  .metadata.labels.name = strenv(namespace)
' "${SCRIPT_DIR}"/addon/namespace.yaml >"${namespace_config_path}"
}

# Function to generate the complete set of the config.
function generate_complete_addon_config {
  local generated_config_dir="${1:?}"
  local patch_content_dir="${2:?}"
  local create_namespace="${3:?}"
  local create_gcr_secret="${4:?}"
  local cilium_image_ref="${5:?}"
  local operator_image_ref="${6:?}"
  # addon_config_name is the actually name of the file being uploaded to gcs.
  local addon_config_name="${7:?}"
  local namespace_name="${8:?}"
  local cluster_id="${9:-}"
  local tmp_dir

  tmp_dir="$(mktemp -d -t generated_content.XXXXX)"
  trap 'rm -r "${tmp_dir}"; trap - RETURN' RETURN

  local namespace_config_path=${generated_config_dir}/addon_configuration_namespace.yaml
  local addon_configuration_only_path=${generated_config_dir}/addon_configuration.yaml
  local gcr_secret_config_path=${generated_config_dir}/gcr_secret-config.yaml
  local gcr_secret_name=anthos-networking-ci-registry-token

  # Process content for addon configurations.
  if [[ -n $(find "${PATCH_CONTENT_DIR}" -name "kustomization*") ]]; then
    kubectl kustomize "${patch_content_dir}" -o "${tmp_dir}"/
    # Delete the generated placeholder var file.
    find "${tmp_dir}"/ -name 'default_v1_configmap_vars-*' -delete
  else
    cp "${PATCH_CONTENT_DIR}"/* "${tmp_dir}"/
  fi

  update_operator_image "${operator_image_ref}" "${tmp_dir}"
  update_cilium_image "${cilium_image_ref}" "${tmp_dir}"
  update_cilium_cluster_name_id "${cluster_id}" "${tmp_dir}"
  if [[ ${create_gcr_secret} = true ]]; then
    generated_serviceaccount_yaml=$(find "${tmp_dir}"/ -name '*serviceaccount*')
    if [[ -n ${generated_serviceaccount_yaml} ]]; then
      attach_sa_secret "${gcr_secret_name}" "${generated_serviceaccount_yaml}" "${generated_serviceaccount_yaml}"
    fi
  fi
  generate_addon_config "${addon_configuration_only_path}" "${namespace_name}" "${patch_content_dir}" "${tmp_dir}"

  # Remove full addon config if it already exists.
  if [[ -f "${addon_config_name}" ]]; then
    rm "${addon_config_name}"
  fi

  cat "${addon_configuration_only_path}" >"${addon_config_name}"
  # Only baremetal-gke need namespace config.
  if [[ ${create_namespace} = true ]]; then
    # Process the namespace config
    generate_namespace_config "${namespace_config_path}" "${namespace_name}"
    # Merge the two configurations, print them one by one to ensure the
    # namespace is created before the addon config.
    awk 'FNR==1{print "---"}{print}' "${namespace_config_path}" "${addon_configuration_only_path}" | sed '1d' >"${addon_config_name}"
  fi

  if [[ ${create_gcr_secret} = true ]]; then
    # Merge the two configurations, print them one by one to ensure the
    # secret is created before the addon config.
    generate_gcr_secret_config "${gcr_secret_config_path}" "${gcr_secret_name}"
    # Attach secret to default sa.
    attach_sa_secret "${gcr_secret_name}" "${SCRIPT_DIR}/addon/default_serviceaccount.yaml" "${generated_config_dir}/updated_default_serviceaccount.yaml"
    # Attach secret to cilium-operator sa.
    attach_sa_secret "${gcr_secret_name}" "${SCRIPT_DIR}/addon/cilium_operator_serviceaccount.yaml" "${generated_config_dir}/updated_cilium_operator_serviceaccount.yaml"
    # Combine yaml files in order
    awk 'FNR==1{print "---"}{print}' "${gcr_secret_config_path}" "${generated_config_dir}/updated_default_serviceaccount.yaml" "${generated_config_dir}/updated_cilium_operator_serviceaccount.yaml" "${addon_configuration_only_path}" | sed '1d' >"${addon_config_name}"
  fi
}

# --------------------- function definitions done -----------------------------

rm -rf "${GENERATED_CONFIGS_DIR}"
mkdir -p "${GENERATED_CONFIGS_DIR}"

local_addon_config_path="${WORKDIR}/$(basename "${ADDON_CONFIG_URL}")"

generate_complete_addon_config "${GENERATED_CONFIGS_DIR}" "${PATCH_CONTENT_DIR}" "${CREATE_NAMESPACE}" "${CREATE_GCR_SECRET}" "${CILIUM_IMAGE_REF}" "${OPERATOR_IMAGE_REF}" "${local_addon_config_path}" "${CLUSTER_NAMESPACE}" "${CLUSTER_ID}"

# Push the configuration to gcs bucket.
gcloud storage cp "${local_addon_config_path}" "${ADDON_CONFIG_URL}"
