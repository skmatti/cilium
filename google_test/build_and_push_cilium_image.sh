#!/bin/bash
# This a helper script to build and push cilium images.

set -ex
# Variables below are not required for docker version >= 23.
export DOCKER_BUILDKIT=1
export DOCKER_CLI_EXPERIMENTAL=enabled

export PS4='+ $(date "+%Y/%m/%d %H:%M:%S"): '

# Ensure IMAGE_REGISTRY is set.
: "${IMAGE_REGISTRY:?}"

# Register gcloud as the credential helper for Google-supported Docker registries.
gcloud auth configure-docker --quiet
gcloud auth configure-docker "${IMAGE_REGISTRY%%/*}" --quiet

function build_and_push_if_absent {
    local image="${1:?}"
    local target="${2:?}"
    local image_registry="${3:?}"
    if gcloud container images describe "${image}" > /dev/null 2>&1; then
        echo "Found: ${image}, skip building"
    else
        echo "${image} not available"
        make -B LOCKDEBUG=1 DOCKER_REGISTRY="${image_registry}" "${target}"
        docker push "${image}"
    fi
}

declare -A images_to_check
operator_image="${IMAGE_REGISTRY}/cilium/operator-generic:${DOCKER_IMAGE_TAG:?}"
cilium_image="${IMAGE_REGISTRY}/cilium/cilium:${CILIUM_DOCKER_IMAGE_TAG:?}"
images_to_check["${operator_image}"]="docker-operator-generic-image"
images_to_check["${cilium_image}"]="docker-cilium-dpv2-image"

if [[ "${NUM_CLUSTERS:-1}" -gt 1 ]]; then
    cilium_clustermesh_image="${IMAGE_REGISTRY}/cilium/clustermesh-apiserver:${DOCKER_IMAGE_TAG}"
    images_to_check["${cilium_clustermesh_image}"]="docker-clustermesh-apiserver-image"
fi

for image in "${!images_to_check[@]}"; do
    build_and_push_if_absent "${image}" "${images_to_check[${image}]}" "${IMAGE_REGISTRY}"
done
