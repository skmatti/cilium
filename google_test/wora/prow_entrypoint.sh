#!/bin/bash

set -euxo pipefail
shopt -s inherit_errexit

ROOT="$(dirname -- "${BASH_SOURCE[0]}")"

# For manual runs:
#  - set RUN_DOWN=false

# Users may set RUN_ID or BUILD_ID or PROW_JOB_ID for manual tests.
# BUILD_ID will be used for tests run with Prow.
RUN_ID="${RUN_ID:-"${BUILD_ID:-"${PROW_JOB_ID:-}"}"}"
if [[ -z "${RUN_ID}" ]]; then
  echo "RUN_ID is not set. Please set RUN_ID (preferred), BUILD_ID or PROW_JOB_ID." >&2
  exit 1
fi
echo "RUN_ID is set to: ${RUN_ID}"
export RUN_ID

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
  local num_clusters="${3:?}"
  local current_branch
  local docker_image_tag
  local cilium_docker_image_tag

  current_branch="$(git rev-parse --abbrev-ref HEAD)"
  if [[ "${cilium_gitref}" = "${current_branch}" ]] || [[ "${cilium_gitref}" = HEAD ]]; then
    # Build and push cilium from current branch HEAD.
    echo "INFO: building image from CILIUM_GITREF:HEAD." >&2
    docker_image_tag="$(git rev-parse --verify HEAD)"
    cilium_docker_image_tag=${docker_image_tag}-dpv2
    IMAGE_REGISTRY=${image_registry} \
    DOCKER_IMAGE_TAG=${docker_image_tag} \
    CILIUM_DOCKER_IMAGE_TAG=${cilium_docker_image_tag} \
    NUM_CLUSTERS=${num_clusters} \
    "${ROOT}/../build_and_push_cilium_image.sh"
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

    IMAGE_REGISTRY=${image_registry} \
    DOCKER_IMAGE_TAG=${docker_image_tag} \
    CILIUM_DOCKER_IMAGE_TAG=${cilium_docker_image_tag} \
    NUM_CLUSTERS=${num_clusters} \
    ./build_and_push_cilium_image.sh
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

# Function to insert the resource owner into a rookery.
function insert_resource_owner {
  local config="${1:?}"
  local owner="${2:?}"

  env owner="${owner}" \
    yq -i '.spec.resourceOwner = strenv(owner)' "${config}"
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

# Function to determine the number of clusters requested in the config.
function num_clusters {
  local -r config="${1:?}"
  yq '.spec.knests[] | .spec.clusters | length' "${config}"
}

# Find out what platform we are running against.
PLATFORM=$(cluster_platform "${TBCONFIG}")

# Remove proxy env on platforms where it is not supported.
if [[ ${PLATFORM} = gcp-gke ]]; then
  remove_env "${WORA_CONFIG}" HTTPS_PROXY HTTP_PROXY
fi

# Find out how many clusters are requested in the config.
NUM_CLUSTERS=$(num_clusters "${TBCONFIG}")

# The following functions are used to add support for multistage and
# multicluster tests in abm.

function split_csv_to_lines_with_default {
  local csv_string="${1:?}"
  local default_value="${2:?}"
  local item

  if [[ -z "${csv_string}" ]]; then
    return 0
  fi

  local -a items
  # shellcheck disable=SC2312
  mapfile -t items < <(echo "${csv_string}" | tr ',' '\n' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')

  for item in "${items[@]}"; do
    if [[ "${item}" = "_" ]]; then
      item="${default_value}"
    fi
    echo "${item}"
  done
}

function validate_array_with_length {
  local expected_length="${1:?}"
  local -n arr="${2:?}" # nameref to the array
  if [[ "${#arr[@]}" != "${expected_length}" ]]; then
    echo "The number of items in array '${2}' (${#arr[@]}) does not match the expected length (${expected_length})." >&2
    exit 1
  fi
}

function create_addon_config_urls {
  local array_length="${1:?}"
  local -n arr="${2:?}"
  local prefix="${3:?}"
  local name="${4:?}"
  local suffix="${5:?}"

  if [[ "${array_length}" -eq 1 ]]; then
    arr=("${prefix}/${name}${suffix}")
    return
  fi

  arr=()
  for i in $(seq 1 "${array_length}"); do
    arr+=("${prefix}/${name}-${i}${suffix}")
  done
}

# Find out if we are running a multistage test.
if [[ -v TARGET_CILIUM_IMAGES_WITH_TAG || -v TARGET_CILIUM_OPERATOR_IMAGES_WITH_TAG || -v TARGET_PATCH_CONTENT_DIR ]]; then
  IS_MULTISTAGE=true
else
  IS_MULTISTAGE=false
fi
export IS_MULTISTAGE

# Check that platform is baremetal-gke for multicluster or multistage.
if [[ "${PLATFORM}" != "baremetal-gke" ]]; then
  if [[ "${NUM_CLUSTERS}" -gt 1 ]]; then
    echo "Multiple clusters are only supported for baremetal-gke platform." >&2
    echo "PLATFORM=${PLATFORM}" >&2
    exit 1
  fi
  if [[ "${IS_MULTISTAGE}" = "true" ]]; then
    echo "Multistage tests are only supported for baremetal-gke platform." >&2
    echo "TARGET_CILIUM_IMAGES_WITH_TAG=${TARGET_CILIUM_IMAGES_WITH_TAG}" >&2
    echo "TARGET_CILIUM_OPERATOR_IMAGES_WITH_TAG=${TARGET_CILIUM_OPERATOR_IMAGES_WITH_TAG}" >&2
    echo "TARGET_PATCH_CONTENT_DIR=${TARGET_PATCH_CONTENT_DIR}" >&2
    exit 1
  fi
fi

# Insert resource owner into SUT and WORA config.
insert_resource_owner "${TBCONFIG}" "${JOB_SPEC:-"${USER}"}"
insert_resource_owner "${WORA_CONFIG}" "${JOB_SPEC:-"${USER}"}"

# Set up building and pushing images and add-on configs.
PROJECT=${GCP_PROJECT:-"anthos-networking-ci"}
IMAGE_REGISTRY=${IMAGE_REGISTRY:-"gcr.io/${PROJECT}"}
DOCKER_IMAGE_TAG=${DOCKER_IMAGE_TAG:-}
CILIUM_DOCKER_IMAGE_TAG=${CILIUM_DOCKER_IMAGE_TAG:-}
ADDON_CONFIG_NAME=addonConfig-${RUN_ID}
ADDON_CONFIG_BUCKET_URL=gs://anthos-networking-ci-artifacts/addon-configs
# PATCH_CONTENT_DIR defaults to an option that only patches the Cilium
# and Cilium operator images. See http://b/327682436#comment3.
DEFAULT_PATCH_CONTENT_DIR="addon/patch_content/abm-1.32.x-gke/overlays/image-only"

# Build the corresponding Cilium images and upload to the registry.
# This step is only performed if CILIUM_GITREF is specified.
if [[ -n "${CILIUM_GITREF:-}" ]]; then

  # Only build and push images when the image tags are not specified,
  # DOCKER_IMAGE_TAG and CILIUM_DOCKER_IMAGE_TAG will also be updated here.
  if [[ -z "${DOCKER_IMAGE_TAG}" ]] || [[ -z "${CILIUM_DOCKER_IMAGE_TAG}" ]]; then
    build_and_push_cilium_image "${CILIUM_GITREF}" "${IMAGE_REGISTRY}" "${NUM_CLUSTERS}"
  fi
fi

function provision_abm {
  local default_cilium_image_with_tag=${IMAGE_REGISTRY}/cilium/cilium:${CILIUM_DOCKER_IMAGE_TAG}
  local default_operator_image_with_tag=${IMAGE_REGISTRY}/cilium/operator-generic:${DOCKER_IMAGE_TAG}
  local -a cilium_images_with_tag
  local -a operator_images_with_tag
  local -a patch_content_dirs
  local -a addon_config_urls

  local default_csv="_"
  for i in $(seq 2 "${NUM_CLUSTERS}"); do
    default_csv+=",_"
  done

  mapfile -t cilium_images_with_tag < <(split_csv_to_lines_with_default "${CILIUM_IMAGES_WITH_TAG:-${default_csv}}" "${default_cilium_image_with_tag}")
  mapfile -t operator_images_with_tag < <(split_csv_to_lines_with_default "${CILIUM_OPERATOR_IMAGES_WITH_TAG:-${default_csv}}" "${default_operator_image_with_tag}")
  mapfile -t patch_content_dirs < <(split_csv_to_lines_with_default "${PATCH_CONTENT_DIR:-${default_csv}}" "${DEFAULT_PATCH_CONTENT_DIR}")

  # All tests: number of images match number of clusters.
  for arr in "cilium_images_with_tag" "operator_images_with_tag" "patch_content_dirs"; do
    validate_array_with_length "${NUM_CLUSTERS}" "${arr}"
  done

  # Define add-on config urls.
  create_addon_config_urls "${NUM_CLUSTERS}" addon_config_urls "${ADDON_CONFIG_BUCKET_URL}" "${ADDON_CONFIG_NAME}" ".yaml"

  # Multistage tests: if set, number of images match number of clusters.
  if [[ "${IS_MULTISTAGE}" = "true" ]]; then
    local -a target_cilium_images_with_tag
    local -a target_operator_images_with_tag
    local -a target_patch_content_dirs
    local -a target_addon_config_urls
    mapfile -t target_cilium_images_with_tag < <(split_csv_to_lines_with_default "${TARGET_CILIUM_IMAGES_WITH_TAG:-${default_csv}}" "${default_cilium_image_with_tag}")
    mapfile -t target_operator_images_with_tag < <(split_csv_to_lines_with_default "${TARGET_CILIUM_OPERATOR_IMAGES_WITH_TAG:-${default_csv}}" "${default_operator_image_with_tag}")
    mapfile -t target_patch_content_dirs < <(split_csv_to_lines_with_default "${TARGET_PATCH_CONTENT_DIR:-${default_csv}}" "${DEFAULT_PATCH_CONTENT_DIR}")

    # Multistage tests: number of images match number of clusters.
    for arr in "target_cilium_images_with_tag" "target_operator_images_with_tag" "target_patch_content_dirs"; do
      validate_array_with_length "${NUM_CLUSTERS}" "${arr}"
    done

    # Define add-on config urls for multistage tests.
    create_addon_config_urls "${NUM_CLUSTERS}" target_addon_config_urls "${ADDON_CONFIG_BUCKET_URL}" "${ADDON_CONFIG_NAME}-target" ".yaml"
    export MULTISTAGE_ADDON_CONFIG_GSPATH="${target_addon_config_urls[0]}"
  fi

  local add_suffix
  if [[ "${NUM_CLUSTERS}" -gt 1 ]]; then
    add_suffix="true"
  else
    add_suffix="false"
  fi

  # Generate add-on configurations for each cluster.
  for i in $(seq 1 "${NUM_CLUSTERS}"); do
    j=$((i - 1))
    env \
      ABSOLUTE_PATH_TBCONFIG="${TBCONFIG}" \
      ADD_SUFFIX="${add_suffix}" \
      ADDON_CONFIG_URL="${addon_config_urls[${j}]}" \
      CREATE_NAMESPACE="true" \
      CILIUM_IMAGE_REF="${cilium_images_with_tag[${j}]}" \
      OPERATOR_IMAGE_REF="${operator_images_with_tag[${j}]}" \
      PATCH_CONTENT_DIR="${ROOT}/${patch_content_dirs[${j}]}" \
      CLUSTER_ID="${i}" \
      WORKDIR="${ROOT}/${WORKDIR}" \
      CILIUM_GITREF="${CILIUM_GITREF:-}" \
      RUN_ID="${RUN_ID}" \
      "${ROOT}/provision_abm.sh"
  done

  # Multistage tests: if set, generate add-on configurations for each target cluster.
  if [[ "${IS_MULTISTAGE}" = "true" ]]; then
    for i in $(seq 1 "${NUM_CLUSTERS}"); do
      j=$((i - 1))
      env \
        ABSOLUTE_PATH_TBCONFIG="${TBCONFIG}" \
        ADD_SUFFIX="${add_suffix}" \
        ADDON_CONFIG_URL="${target_addon_config_urls[${j}]}" \
        GENERATE_ADDON_ONLY="true" \
        CREATE_NAMESPACE="false" \
        CILIUM_IMAGE_REF="${target_cilium_images_with_tag[${j}]}" \
        OPERATOR_IMAGE_REF="${target_operator_images_with_tag[${j}]}" \
        PATCH_CONTENT_DIR="${ROOT}/${target_patch_content_dirs[${j}]}" \
        CLUSTER_ID="${i}" \
        WORKDIR="${ROOT}/${WORKDIR}" \
        CILIUM_GITREF="${CILIUM_GITREF:-}" \
        RUN_ID="${RUN_ID}" \
        "${ROOT}/provision_abm.sh"
    done
  fi
}

# Update the cluster rookery file.
case "${PLATFORM}" in
  baremetal-gke)
    provision_abm
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
  gcp-gke)
    make -C "${ROOT}" \
      ADVANCEDDATAPATH_IMAGE_SUFFIX="${CILIUM_GITREF:+"${RUN_ID}"}" \
      DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG}" \
      CILIUM_DOCKER_IMAGE_TAG="${CILIUM_DOCKER_IMAGE_TAG}" \
      TBCONFIG="$(realpath "${TBCONFIG}" || true)" \
      CILIUM_GITREF="${CILIUM_GITREF:-}" \
      configure-docker provision-gke
    if [[ -n "${CILIUM_GITREF:-}" ]]; then
      make -C "${ROOT}" \
        ADVANCEDDATAPATH_IMAGE_SUFFIX="${RUN_ID}" \
        ${ADVANCEDDATAPATH_BASE_IMAGE_TAG+ADVANCEDDATAPATH_BASE_IMAGE_TAG="${ADVANCEDDATAPATH_BASE_IMAGE_TAG}"} \
        IMAGE_REGISTRY="${IMAGE_REGISTRY}" \
        DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG}" \
        CILIUM_DOCKER_IMAGE_TAG="${CILIUM_DOCKER_IMAGE_TAG}" \
        TBCONFIG="$(realpath "${TBCONFIG}" || true)" \
        CILIUM_GITREF="${CILIUM_GITREF}" \
        advanceddatapath-image push-advanceddatapath-image
    fi
    ;;
  gdch-gdch-gce-adhoc)
    OC_UPDATE_TEMPLATE="${OC_UPDATE_TEMPLATE:-"cilium_129_update_spec.json.tmpl"}"
    ENV_TEMPLATE_ID="${ENV_TEMPLATE_ID:-"c97a9292-975e-47f3-a290-a70df10edc4f"}"
    GDCH_E2E_TESTS="${GDCH_E2E_TESTS:-}"
    GDCH_E2E_TEST_PLAN="${GDCH_E2E_TEST_PLAN:-}"
    GDCH_E2E_START_AT_TEST="${GDCH_E2E_START_AT_TEST:-}"
    ADHOC_USERNAME=${ADHOC_USERNAME:-"ci-an-shift-left"}
    working_copy "${ROOT}/oc_update/${OC_UPDATE_TEMPLATE}" "${ROOT}/${WORKDIR}"
    ABSOLUTE_PATH_TBCONFIG="${TBCONFIG}" \
      IMAGE_REGISTRY="${IMAGE_REGISTRY}" \
      DOCKER_IMAGE_TAG="${DOCKER_IMAGE_TAG}" \
      CILIUM_DOCKER_IMAGE_TAG="${CILIUM_DOCKER_IMAGE_TAG}" \
      WORKDIR="${ROOT}/${WORKDIR}" \
      CILIUM_GITREF="${CILIUM_GITREF:-}" \
      OC_UPDATE_TEMPLATE="${OC_UPDATE_TEMPLATE}" \
      ENV_TEMPLATE_ID="${ENV_TEMPLATE_ID}" \
      GDCH_E2E_TESTS="${GDCH_E2E_TESTS}" \
      GDCH_E2E_TEST_PLAN="${GDCH_E2E_TEST_PLAN}" \
      GDCH_E2E_START_AT_TEST="${GDCH_E2E_START_AT_TEST}" \
      ADHOC_USERNAME="${ADHOC_USERNAME:-}" \
      "${ROOT}/provision_gdch.sh"
    # Unset docker image after upgrade to stop failures due to image verification.
    # Image verification is not possible in GDCH due to lack of kubeconfig support.
    DISABLE_UPGRADE_VERIFICATION=true
    TB_CLIENT_TIMEOUT=10h
    ;;
  *)
    echo "Unknown platform: ${PLATFORM}." >&2
    exit 1
    ;;
esac

# Build and push plugin image if WORA_IMAGE_TAG is not set.
if [[ -z "${WORA_IMAGE_TAG:-}" ]]; then
  WORA_IMAGE_TAG="${RUN_ID}"
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

function update_label_filter {
  local config="${1:?}"
  local label_filter="${2:?}"
  yq -i "(.spec.applications[].spec.directives[].spec.args[]
    | select(. == \"--label-filter=*\"))
    |= \"--label-filter=${label_filter}\"" "${config}"
}

function update_cluster_type {
  local config="${1:?}"
  local cluster_type="${2:?}"
  yq -i "(.spec.applications[].spec.directives[].spec.args[]
    | select(. == \"--cluster-type=*\"))
    |= \"--cluster-type=${cluster_type}\"" "${config}"
}


function insert_clustermesh_image {
  local -r config="${1:?}"
  local -r clustermesh_image="${2:?}"

  export clustermesh_image
  yq -i '.spec.applications.[0].spec.directives.[0].spec.env.CILIUM_CLUSTERMESH_IMAGE_WITH_TAG = env(clustermesh_image)' "${config}"
}


function insert_cilium_version_check() {
  local config="${1:?}"
  local image_with_tag="${2:?}"
  env \
    image_with_tag="${image_with_tag}" \
    yq -i '
    .spec.applications[] |= (
      select(.spec.resourceTypeReference.name == "k8s-net-post-provisioner") |
      .spec.directives[] |= (
        (.spec.env.POSTPROVISIONER_FEATURES |= ([., "checkversions"] | join(","))) |
        (.spec.env.CILIUM_IMAGE_WITH_TAG = strenv(image_with_tag))
      )
    )' "${config}"
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

# Update ginkgo label filter in WORA_CONFIG.
# This function assumes that `--label-filter` is already defined in WORA_CONFIG.
if [[ -v WORA_GINKGO_LABEL_FILTER ]]; then
  update_label_filter "${WORA_CONFIG}" "${WORA_GINKGO_LABEL_FILTER:-}"
fi

# This function assumes that `--cluster-type` is already defined in WORA_CONFIG.
if [[ -v WORA_GINKGO_CLUSTER_TYPE ]]; then
  update_cluster_type "${WORA_CONFIG}" "${WORA_GINKGO_CLUSTER_TYPE:-}"
fi

if [[ -n "${CILIUM_DOCKER_IMAGE_TAG}" ]] && [[ "${DISABLE_UPGRADE_VERIFICATION:-"false"}" != "true" ]]; then
  insert_cilium_version_check \
    "${TBCONFIG}" \
    "${IMAGE_REGISTRY}/cilium/cilium:${CILIUM_DOCKER_IMAGE_TAG}"
fi

if [[ "${NUM_CLUSTERS}" -gt 1 ]]; then
  CILIUM_CLUSTERMESH_IMAGE_WITH_TAG=${IMAGE_REGISTRY}/cilium/clustermesh-apiserver:${DOCKER_IMAGE_TAG}
  export CILIUM_CLUSTERMESH_IMAGE_WITH_TAG
  insert_clustermesh_image \
    "${TBCONFIG}" \
    "${CILIUM_CLUSTERMESH_IMAGE_WITH_TAG}"
fi

# Runs the cluster-debug-links tool in a Docker container to generate
# debugging links for a given test cluster.
function add_cluster_debug_links {
  local tbconfig="${1:?}"
  local project="${2:?}"
  local starttime="${3:?}"
  local artifacts_dir="${4:?}"

  local container_tbconfig_path="/config/tbconfig.yaml"
  local container_artifacts_dir="/artifacts"

  local tool_image="us-docker.pkg.dev/anthos-networking-ci/apps/cluster-debug-links:latest"
  echo "Running cluster-debug-links container..." >&2
  gcloud auth configure-docker us-docker.pkg.dev --quiet
  docker run --pull=always -d \
    -v "${tbconfig}":"${container_tbconfig_path}":ro \
    -v "${artifacts_dir}":"${container_artifacts_dir}" \
    "${tool_image}" cluster-debug-links \
      --tbconfig="${container_tbconfig_path}" \
      --project="${project}" \
      --output-dir="${container_artifacts_dir}" \
      --starttime="${starttime}"
  echo "cluster-debug-links container finished successfully." >&2
}

# Generate debugging links.
add_cluster_debug_links \
  "${TBCONFIG}" \
  "${PROJECT}" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  "${ARTIFACTS:-${ROOT}/${WORKDIR}}"

# Runs the snapshot-cluster-logs tool in a Docker container to snapshot
# clusters.
function snapshot_cluster_logs {
  local artifacts_dir="${1:?}"

  local tool_image="us-docker.pkg.dev/anthos-networking-ci/apps/snapshot-cluster-logs:latest"
  echo "Running snapshot-cluster-logs container..." >&2
  if docker run --pull=always \
    -v "${artifacts_dir}":"${artifacts_dir}" \
    "${tool_image}" snapshot-cluster-logs \
      --artifacts-dir="${artifacts_dir}"; then
    echo "snapshot-cluster-logs container finished successfully." >&2
  else
    echo "Warning: snapshot-cluster-logs container did not finish successfully. Continuing with script." >&2
  fi
}

trap '
  # Snapshot clusters. This function ignores errors.
  snapshot_cluster_logs "${ARTIFACTS:-"${ROOT}/${WORKDIR}"}${ARTIFACTS:+/"${RUN_ID}"}"

  # Run kubetest2-tailorbird teardown.
  kubetest2-tailorbird \
  --verbose \
  --run-id="${RUN_ID}" \
  --down="${RUN_DOWN:-true}" \
  --tbconfig="${TBCONFIG}" \
  --tbenv="${TBENV}"
  ' EXIT

kubetest2-tailorbird \
--verbose \
--run-id="${RUN_ID}" \
--up \
--tbconfig="${TBCONFIG}" \
--tbenv="${TBENV}" \
--client-timeout="${TB_CLIENT_TIMEOUT:-3h}" \
--test=exec \
-- \
"${ROOT}/run.sh"
