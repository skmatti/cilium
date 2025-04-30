#!/bin/bash
# This a helper script to build and push cilium images.

set -ex
# Variables below are not required for docker version >= 23.
export DOCKER_BUILDKIT=1
export DOCKER_CLI_EXPERIMENTAL=enabled

# Ensure IMAGE_REGISTRY is set.
: "${IMAGE_REGISTRY:?}"

# Register gcloud as the credential helper for Google-supported Docker registries.
gcloud auth configure-docker --quiet
gcloud auth configure-docker "${IMAGE_REGISTRY%%/*}" --quiet
# Build and push cilium to google cloud registry
echo "Making Cilium images for current HEAD and push to google cloud registry: ${IMAGE_REGISTRY}"
make -B LOCKDEBUG=1 DOCKER_REGISTRY="${IMAGE_REGISTRY}" docker-operator-generic-image
docker push "${IMAGE_REGISTRY}/cilium/operator-generic:${DOCKER_IMAGE_TAG:?}"

make -B LOCKDEBUG=1 DOCKER_REGISTRY="${IMAGE_REGISTRY}" docker-cilium-dpv2-image
docker push "${IMAGE_REGISTRY}/cilium/cilium:${CILIUM_DOCKER_IMAGE_TAG:?}"

if [[ "${NUM_CLUSTERS:-1}" -gt 1 ]]; then
    make -B LOCKDEBUG=1 DOCKER_REGISTRY="${IMAGE_REGISTRY}" docker-clustermesh-apiserver-image
    docker push "${IMAGE_REGISTRY}/cilium/clustermesh-apiserver:${DOCKER_IMAGE_TAG}"
fi
