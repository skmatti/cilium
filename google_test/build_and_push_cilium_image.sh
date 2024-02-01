#!/bin/bash
# This a helper script to build and push cilium images.

set -ex
# Variables below are not required for docker version >= 23.
export DOCKER_BUILDKIT=1
export DOCKER_CLI_EXPERIMENTAL=enabled

# Register gcloud as the credential helper for Google-supported Docker registries.
gcloud auth configure-docker
# Build and push cilium to google cloud registry
echo "Making Cilium images for current HEAD and push to google cloud registry: ${IMAGE_REGISTRY}"
make -B LOCKDEBUG=1 DOCKER_REGISTRY="${IMAGE_REGISTRY}" docker-operator-generic-image
docker push "${IMAGE_REGISTRY}/cilium/operator-generic:${DOCKER_IMAGE_TAG}"

make -B LOCKDEBUG=1 DOCKER_REGISTRY="${IMAGE_REGISTRY}" docker-cilium-dpv2-image
docker push "${IMAGE_REGISTRY}/cilium/cilium:${CILIUM_DOCKER_IMAGE_TAG}"
