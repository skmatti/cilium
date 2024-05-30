#!/bin/bash
# This script will be called by prow_entrypoint.sh to create an
# AddOnConfiguration yaml file and upload it to a given gcs bucket destination.

set -ex
SCRIPT_DIR=$(dirname -- "${BASH_SOURCE[0]}")
WORKDIR=${WORKDIR:-${SCRIPT_DIR}}
GENERATED_CONFIGS_DIR="${GENERATED_CONFIGS_DIR:-"${WORKDIR}/generated_configs"}"
PATCH_CONTENT_DIR="${PATCH_CONTENT_DIR:-"${SCRIPT_DIR}/addon/patch_content/abm-1.29.100-gke.76/overlays/image-only"}"

if [[ -z ${PROW_JOB_ID:-} ]]; then
  echo "ERROR: must specify PROW_JOB_ID." >&2
  exit 1
fi

if [[ -z ${CREATE_NAMESPACE:-} ]]; then
  echo "ERROR: must specify CREATE_NAMESPACE." >&2
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

if [[ -z ${ADDON_CONFIG_BUCKET_URL:-} ]]; then
  echo "ERROR: must specify ADDON_CONFIG_BUCKET_URL, the path to GCS bucket folder where the Tailorbird can access the addon Configuration." >&2
  exit 1
fi

if [[ -z ${ADDON_CONFIG_NAME:-} ]]; then
  echo "ERROR: must specify ADDON_CONFIG_NAME, the name of the addon Configuration." >&2
  exit 1
fi

if [[ -z ${IMAGE_REGISTRY:-} ]]; then
  echo "ERROR: must specify IMAGE_REGISTRY, the base registry for docker images." >&2
  exit 1
fi

if [[ -z ${DOCKER_IMAGE_TAG:-} ]]; then
  echo "ERROR: must specify DOCKER_IMAGE_TAG, the image tag for docker images other than cilium." >&2
  exit 1
fi

# Cilium image built by internal target have a suffix as -dpv2, see details in
# https://source.corp.google.com/h/gke-internal/third_party/cilium/+/master:Makefile.docker.google;l=47;drc=6f2df58eb047ac3ff455fe3930c0a90f8ed8a949
if [[ -z ${CILIUM_DOCKER_IMAGE_TAG:-} ]]; then
  echo "ERROR: must specify CILIUM_DOCKER_IMAGE_TAG, the image tag for cilium docker images. In google:cilium the cilium image built by internal target have a suffix as -dpv2."
  exit 1
fi

echo "PROW_JOB_ID             = ${PROW_JOB_ID}"
echo "CREATE_NAMESPACE        = ${CREATE_NAMESPACE}"
echo "CREATE_GCR_SECRET       = ${CREATE_GCR_SECRET}"
echo "BMCTL_VERSION           = ${BMCTL_VERSION}"
echo "ADDON_CONFIG_BUCKET_URL = ${ADDON_CONFIG_BUCKET_URL}"
echo "ADDON_CONFIG_NAME       = ${ADDON_CONFIG_NAME}"
echo "IMAGE_REGISTRY          = ${IMAGE_REGISTRY}"
echo "DOCKER_IMAGE_TAG        = ${DOCKER_IMAGE_TAG}"
echo "WORKDIR                 = ${WORKDIR}"

# Function to update the image for operator.yaml
function update_operator_image {
  local registry="${1:?}"
  local tag="${2:?}"
  local generated_content_tmp_dir="${3:?}"
  generated_operator_yaml=${generated_content_tmp_dir}/$(find "${generated_content_tmp_dir}"/ -name '*anet-operator*' | sed "s/.*\///")
  local image="${registry}/cilium/operator-generic:${tag}"
  export image
  yq -i '(.spec.template.spec.containers[] | select(.name=="cilium-operator") | .image) = strenv(image)' "${generated_operator_yaml}"
}

# Function to update the image for anet.yaml
function update_cilium_image {
  local registry="${1:?}"
  local tag="${2:?}"
  local generated_content_tmp_dir="${3:?}"
  generated_anet_yaml=${generated_content_tmp_dir}/$(find "${generated_content_tmp_dir}"/ -name '*anetd*' | sed "s/.*\///")
  local image="${registry}/cilium/cilium:${tag}"
  export image
  yq -i '(.spec.template.spec.containers[] | select(.image=="*/cilium/cilium:*") | .image) = strenv(image)' "${generated_anet_yaml}"
  yq -i '(.spec.template.spec.initContainers[] | select(.image=="*/cilium/cilium:*") | .image) = strenv(image)' "${generated_anet_yaml}"
}

# Function to attach generated secret to the given sa config.
function attach_sa_secret {
  local gcr_secret_name="${1:?}"
  export gcr_secret_name
  local original_sa_config_path="${2:?}"
  local updated_sa_config_path="${3:?}"

  if [[ "${original_sa_config_path}" != "${updated_sa_config_path}" ]]; then
    cp "${original_sa_config_path}" "${updated_sa_config_path}"
  fi

  yq -i '( .imagePullSecrets += [{"name": strenv(gcr_secret_name)}])' "${updated_sa_config_path}"
}

# Process Addon configuration.
function generate_addon_config {
  local addon_config_path="${1:?}"
  local namespace="${2:?}"
  local patch_content_dir="${3:?}"
  local generated_content_tmp_dir="${4:?}"
  export namespace
  yq '
  .metadata.name = strenv(PROW_JOB_ID) |
  .metadata.namespace = strenv(namespace) |
  .spec.anthosBareMetalVersions[0] = env(BMCTL_VERSION)
' "${SCRIPT_DIR}"/addon/configuration.yaml >"${addon_config_path}"

  for file in "${generated_content_tmp_dir}"/*.yaml; do
    if [ -f "${file}" ]; then
      api_version=$(yq '.apiVersion' "${file}")
      export api_version
      kind=$(yq '.kind' "${file}")
      export kind
      name=$(yq '.metadata.name' "${file}")
      export name
      patch_content=$(cat "${file}")
      export patch_content
      namespace=$(yq '.metadata.namespace' "${file}")
      if [ "${namespace}" != "null" ]; then
        export namespace
        yq -i '.spec.configs += {"apiVersion": strenv(api_version), "kind" : strenv(kind), "name" : strenv(name), "namespace": strenv(namespace), "patchContent" : strenv(patch_content)}' "${addon_config_path}"
      else
        yq -i '.spec.configs += {"apiVersion": strenv(api_version), "kind" : strenv(kind), "name" : strenv(name), "patchContent" : strenv(patch_content)}' "${addon_config_path}"
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
  local image_registry="${5:?}"
  local docker_image_tag="${6:?}"
  local cilium_docker_image_tag="${7:?}"
  # addon_config_name is the actually name of the file being uploaded to gcs.
  local addon_config_name="${8:?}"
  local namespace_name="${9:?}"
  local generated_content_tmp_dir

  generated_content_tmp_dir="$(mktemp -d -t generated_content.XXXXX)"
  trap 'rm -r "${generated_content_tmp_dir}"; trap - RETURN' RETURN

  local namespace_config_path=${generated_config_dir}/addon_configuration_namespace.yaml
  local addon_configuration_only_path=${generated_config_dir}/addon_configuration.yaml
  local gcr_secret_config_path=${generated_config_dir}/gcr_secret-config.yaml
  local gcr_secret_name=anthos-networking-ci-registry-token

  # Process content for addon configurations.
  if [[ -n $(find "${PATCH_CONTENT_DIR}" -name "kustomization*") ]]; then
    kubectl kustomize "${patch_content_dir}" -o "${generated_content_tmp_dir}"/
    # Delete the generated placeholder var file.
    find "${generated_content_tmp_dir}"/ -name 'default_v1_configmap_vars-*' -delete
  else
    cp "${PATCH_CONTENT_DIR}"/* "${generated_content_tmp_dir}"/
  fi

  update_operator_image "${image_registry}" "${docker_image_tag}" "${generated_content_tmp_dir}"
  update_cilium_image "${image_registry}" "${cilium_docker_image_tag}" "${generated_content_tmp_dir}"
  if [[ ${create_gcr_secret} = true ]]; then
    generated_serviceaccount_yaml=$(find "${generated_content_tmp_dir}"/ -name '*serviceaccount*')
    if [[ -n ${generated_serviceaccount_yaml} ]]; then
      attach_sa_secret "${gcr_secret_name}" "${generated_serviceaccount_yaml}" "${generated_serviceaccount_yaml}"
    fi
  fi
  generate_addon_config "${addon_configuration_only_path}" "${namespace_name}" "${patch_content_dir}" "${generated_content_tmp_dir}"

  # Remove full addon config if it already exists.
  if [ -f "${addon_config_name}" ]; then
    rm "${addon_config_name}"
  fi

  # Only baremetal-gke need namespace config.
  if [[ ${create_namespace} = true ]]; then
    # Process the namespace config
    generate_namespace_config "${namespace_config_path}" "${namespace_name}"
    # Merge the two configurations, print them one by one to ensure the
    # namespace is created before the addon config.
    awk 'FNR==1{print "---"}{print}' "${namespace_config_path}" "${addon_configuration_only_path}" | sed '1d' >>"${addon_config_name}"
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
    awk 'FNR==1{print "---"}{print}' "${gcr_secret_config_path}" "${generated_config_dir}/updated_default_serviceaccount.yaml" "${generated_config_dir}/updated_cilium_operator_serviceaccount.yaml" "${addon_configuration_only_path}" | sed '1d' >>"${addon_config_name}"
  fi
}

# --------------------- function definitions done -----------------------------

rm -rf "${GENERATED_CONFIGS_DIR}"
mkdir -p "${GENERATED_CONFIGS_DIR}"
generate_complete_addon_config "${GENERATED_CONFIGS_DIR}" "${PATCH_CONTENT_DIR}" "${CREATE_NAMESPACE}" "${CREATE_GCR_SECRET}" "${IMAGE_REGISTRY}" "${DOCKER_IMAGE_TAG}" "${CILIUM_DOCKER_IMAGE_TAG}" "${WORKDIR}/${ADDON_CONFIG_NAME}" "cluster-${PROW_JOB_ID}-cluster"

# Push the configuration to gcs bucket.
gcloud storage cp "${WORKDIR}/${ADDON_CONFIG_NAME}" "${ADDON_CONFIG_BUCKET_URL}/${ADDON_CONFIG_NAME}"
