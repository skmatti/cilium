#!/bin/bash

set -euxo pipefail
shopt -s inherit_errexit

ROOT="$(dirname -- "${BASH_SOURCE[0]}")"

# For manual runs:
#  - use PROW_JOB_ID to use predictable run id.
#  - set RUN_DOWN=false

TBENV="${TBENV:-prod}"
export TBENV

# This will be used by run.sh to revert KUBECONFIG env var change made by kt2-tb.
# Without this, nested tb controlplane login will write to SUT cluster's kubeconfig.
OLD_KUBECONFIG="${KUBECONFIG:-}"
export OLD_KUBECONFIG

# Create a working directory under a root directory.
# Returned path is relative to the root directory.
function workdir {
  local -r root="${1:?}"
  local dir="${2:-}"
  if [[ -z "${dir}" ]]; then
    pushd "${root}" >/dev/null
    mkdir -p _wora
    dir="$(mktemp -d -p _wora XXXXXXXXXX)"
    popd >/dev/null
  fi
  if ! [[ -d "${root}/${dir}" ]]; then
    echo "Working directory must exist and be a directory: ${root}/${dir}." >&2
    return 1
  fi
  echo "${dir}"
}

# Create a working copy of a file in a destination directory.
function working_copy {
  local -r source="${1:?}"
  local -r dest_dir="${2:?}"
  if ! [[ -f "${source}" ]]; then
    echo "Source file not found: ${source}" >&2
    return 1
  fi
  if ! [[ -d "${dest_dir}" ]]; then
    echo "Destination directory not found: ${dest_dir}" >&2
    return 1
  fi
  local -r dest="${dest_dir}/${source##*/}"
  cp "${source}" "${dest}"
  echo "${dest}"
}

WORKDIR="$(workdir "${ROOT}" "${WORKDIR:-}")"
export WORKDIR

TBCONFIG=$(working_copy "${ROOT}/${TBCONFIG:-"sut-abm-gce.yaml"}" "${ROOT}/${WORKDIR}")
export TBCONFIG

WORA_CONFIG=$(working_copy "${ROOT}/${WORA_CONFIG:-"integration_test.yaml"}" "${ROOT}/${WORKDIR}")
export WORA_CONFIG

WORA_CONTROL_PLANE="${WORA_CONTROL_PLANE:-gcp}"
export WORA_CONTROL_PLANE

# Configure git client for Prow to pull source code.
if [[ -n "${GIT_HTTP_COOKIEFILE:-}" ]]; then
  "${ROOT}/../configure_gitclient.sh"
fi

# Function to build and push cilium images from CILIUM_GITREF.
function build_and_push_cilium_image {
  local cilium_gitref="${1:?}"
  local image_registry="${2:?}"
  local current_branch
  local docker_image_tag
  local cilium_docker_image_tag

  current_branch="$(git rev-parse --abbrev-ref HEAD)"
  if [[ "${cilium_gitref}" = "${current_branch}" ]] || [[ "${cilium_gitref}" = HEAD ]]; then
    # Build and push cilium from current branch HEAD.
    echo "INFO: building image from CILIUM_GITREF:HEAD." >&2
    docker_image_tag="$(git rev-parse --verify HEAD)"
    cilium_docker_image_tag=${docker_image_tag}-dpv2
    IMAGE_REGISTRY=${image_registry} DOCKER_IMAGE_TAG=${docker_image_tag} CILIUM_DOCKER_IMAGE_TAG=${cilium_docker_image_tag} "${ROOT}/../build_and_push_cilium_image.sh"
  else
    # Build and push cilium from CILIUM_GITREF.
    echo "INFO: building image from CILIUM_GITREF:${cilium_gitref}." >&2
    local cilium_srcdir
    cilium_srcdir=$(mktemp -d -t cilium_src.XXXXXXXXXX)
    trap 'rm -rf "${cilium_srcdir}"; trap - RETURN' RETURN
    git clone "https://gke-internal.googlesource.com/third_party/cilium" "${cilium_srcdir}/"
    cp "${ROOT}/../build_and_push_cilium_image.sh" "${cilium_srcdir}"

    pushd "${cilium_srcdir}"
    git checkout "${cilium_gitref}"
    docker_image_tag="$(git rev-parse --verify HEAD)"
    cilium_docker_image_tag=${docker_image_tag}-dpv2

    IMAGE_REGISTRY=${image_registry} DOCKER_IMAGE_TAG=${docker_image_tag} CILIUM_DOCKER_IMAGE_TAG=${cilium_docker_image_tag} ./build_and_push_cilium_image.sh
    popd
  fi

  DOCKER_IMAGE_TAG=${docker_image_tag}
  CILIUM_DOCKER_IMAGE_TAG=${cilium_docker_image_tag}
}

# Function to remove given ENV from WORA config.
function remove_env {
  local config="${1:?}"
  local e
  shift
  for e in "$@"; do
    yq -i "del(.spec.applications[].spec.directives[].spec.env.${e})" "${config}"
  done
}

# Function to determine cluster platform based on provider and distribution values.
function cluster_platform {
  local -r config="${1:?}"
  local provider
  local distribution
  provider="$(yq '.spec.knests.[0].spec.clusters.[0].spec.provider' "${config}")"
  distribution="$(yq '.spec.knests.[0].spec.clusters.[0].spec.distribution' "${config}")"
  echo "${provider}-${distribution}"
}

# Find out what platform we are running against.
PLATFORM=$(cluster_platform "${TBCONFIG}")

# Remove proxy env on platforms where it is not supported.
if [[ ${PLATFORM} = gdce-gke ]] || [[ ${PLATFORM} = gcp-gke ]]; then
  remove_env "${WORA_CONFIG}" HTTPS_PROXY HTTP_PROXY
fi

# Set up building and pushing images and add-on configs.
PROJECT=${GCP_PROJECT:-"anthos-networking-ci"}
IMAGE_REGISTRY=${IMAGE_REGISTRY:-"gcr.io/${PROJECT}/integration-test"}
DOCKER_IMAGE_TAG=${DOCKER_IMAGE_TAG:-}
CILIUM_DOCKER_IMAGE_TAG=${CILIUM_DOCKER_IMAGE_TAG:-}
ADDON_CONFIG_NAME=addonConfig-${PROW_JOB_ID:?}.yaml
ADDON_CONFIG_BUCKET_URL=gs://anthos-networking-ci-artifacts/addon-configs
# PATCH_CONTENT_DIR defaults to an option that only patches the Cilium
# and Cilium operator images. See http://b/327682436#comment3.
PATCH_CONTENT_DIR=${ROOT}/${PATCH_CONTENT_DIR:-addon/patch_content/abm-1.29.100-gke.76/overlays/image-only}

# Build the corresponding Cilium images and upload to the registry.
# This step is only performed if CILIUM_GITREF is specified.
if [[ -n "${CILIUM_GITREF:-}" ]]; then

  # Only build and push images when the image tags are not specified,
  # DOCKER_IMAGE_TAG and CILIUM_DOCKER_IMAGE_TAG will also be updated here.
  if [[ -z "${DOCKER_IMAGE_TAG}" ]] || [[ -z "${CILIUM_DOCKER_IMAGE_TAG}" ]]; then
    build_and_push_cilium_image "${CILIUM_GITREF}" "${IMAGE_REGISTRY}"
  fi
fi

# Update the cluster rookery file.
case "${PLATFORM}" in
  baremetal-gke)
    ABSOLUTE_PATH_TBCONFIG="${TBCONFIG}" \
      ADDON_CONFIG_NAME="${ADDON_CONFIG_NAME}" \
      ADDON_CONFIG_BUCKET_URL="${ADDON_CONFIG_BUCKET_URL}" \
      IMAGE_REGISTRY="${IMAGE_REGISTRY}" \
      DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG}" \
      CREATE_NAMESPACE="false" \
      CILIUM_DOCKER_IMAGE_TAG="${CILIUM_DOCKER_IMAGE_TAG}" \
      PATCH_CONTENT_DIR=${PATCH_CONTENT_DIR} \
      WORKDIR="${ROOT}/${WORKDIR}" \
      CILIUM_GITREF="${CILIUM_GITREF:-}" \
      "${ROOT}/provision_abm.sh"
    ;;
  baremetal-gke-baremetal | vsphere-gke-baremetal)
    ABSOLUTE_PATH_TBCONFIG="${TBCONFIG}" \
      ADDON_CONFIG_NAME="${ADDON_CONFIG_NAME}" \
      ADDON_CONFIG_BUCKET_URL="${ADDON_CONFIG_BUCKET_URL}" \
      IMAGE_REGISTRY="${IMAGE_REGISTRY}" \
      DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG}" \
      CILIUM_DOCKER_IMAGE_TAG="${CILIUM_DOCKER_IMAGE_TAG}" \
      PATCH_CONTENT_DIR=${PATCH_CONTENT_DIR} \
      WORKDIR="${ROOT}/${WORKDIR}" \
      CILIUM_GITREF="${CILIUM_GITREF:-}" \
      "${ROOT}/provision_abm.sh"
    ;;
  gdce-gke)
    working_copy "${ROOT}/gdce_plugin_template.yaml" "${ROOT}/${WORKDIR}"
    ABSOLUTE_PATH_TBCONFIG="${TBCONFIG}" \
      ADDON_CONFIG_NAME="${ADDON_CONFIG_NAME}" \
      ADDON_CONFIG_BUCKET_URL="${ADDON_CONFIG_BUCKET_URL}" \
      IMAGE_REGISTRY="${IMAGE_REGISTRY}" \
      DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG}" \
      CILIUM_DOCKER_IMAGE_TAG="${CILIUM_DOCKER_IMAGE_TAG}" \
      WORKDIR="${ROOT}/${WORKDIR}" \
      CILIUM_GITREF="${CILIUM_GITREF:-}" \
      "${ROOT}/provision_gdce.sh"
    ;;
  gcp-gke)
    make -C "${ROOT}" \
      ADVANCEDDATAPATH_IMAGE_SUFFIX="${CILIUM_GITREF:+"${PROW_JOB_ID}"}" \
      CILIUM_DOCKER_IMAGE_TAG="${CILIUM_DOCKER_IMAGE_TAG}" \
      TBCONFIG="$(realpath "${TBCONFIG}" || true)" \
      CILIUM_GITREF="${CILIUM_GITREF:-}" \
      configure-docker provision-gke
    if [[ -n "${CILIUM_GITREF:-}" ]]; then
      make -C "${ROOT}" \
        ADVANCEDDATAPATH_IMAGE_SUFFIX="${PROW_JOB_ID}" \
        IMAGE_REGISTRY="${IMAGE_REGISTRY}" \
        CILIUM_DOCKER_IMAGE_TAG="${CILIUM_DOCKER_IMAGE_TAG}" \
        TBCONFIG="$(realpath "${TBCONFIG}" || true)" \
        CILIUM_GITREF="${CILIUM_GITREF}" \
        advanceddatapath-image push-advanceddatapath-image
    fi
    ;;
  *)
    echo "Unknown platform: ${PLATFORM}." >&2
    exit 1
    ;;
esac

# Build and push plugin image if WORA_IMAGE_TAG is not set.
if [[ -z "${WORA_IMAGE_TAG:-}" ]]; then
  WORA_IMAGE_TAG="${PROW_JOB_ID}"
  # Export for use in run.sh.
  export WORA_IMAGE_TAG

  make -C "${ROOT}" configure-docker wora-image push-wora-image
fi

function insert_plugin_version {
  local -r config="${1:?}"
  local -r name="${2:?}"
  local -r version="${3:?}"

  yq -i "(.spec.applications[].spec.resourceTypeReference
    | select( .name == \"${name}\" )
    | .version) = \"${version}\"" "${config}"
}

function insert_control_plane {
  local config="${1:?}"
  local name="${2:?}"
  local controlPlane="${3:?}"

  yq -i "(.spec.applications[].spec.resourceTypeReference
    | select( .name == \"${name}\" )
    | .controlPlane) = \"${controlPlane}\"" "${config}"
}

# Insert plugin version into WORA_CONFIG.
insert_plugin_version \
  "${WORA_CONFIG}" \
  "${WORA_RESOURCE_NAME:-"anthos-networking-test-workloads"}" \
  "${WORA_IMAGE_TAG}"

# Insert control plane into WORA_CONFIG.
insert_control_plane \
  "${WORA_CONFIG}" \
  "${WORA_RESOURCE_NAME:-"anthos-networking-test-workloads"}" \
  "${WORA_CONTROL_PLANE}"

if [[ -n "${CILIUM_DOCKER_IMAGE_TAG}" ]]; then
  CILIUM_IMAGE_WITH_TAG=${IMAGE_REGISTRY}/cilium/cilium:${CILIUM_DOCKER_IMAGE_TAG}
fi

CILIUM_IMAGE_WITH_TAG=${CILIUM_IMAGE_WITH_TAG:-} \
  kubetest2-tailorbird \
  --verbose \
  --up \
  --down="${RUN_DOWN:-true}" \
  --tbconfig="${TBCONFIG}" \
  --tbenv="${TBENV}" \
  --test=exec \
  -- \
  "${ROOT}/run.sh"
