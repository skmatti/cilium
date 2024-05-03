ARG BASE_IMAGE_REGISTRY="us-central1-docker.pkg.dev/anthos-networking-ci/gke-component-images"
ARG BASE_IMAGE_NAME="advanceddatapath"
ARG BASE_IMAGE_TAG="0.0.1001"

FROM "${BASE_IMAGE_REGISTRY}/${BASE_IMAGE_NAME}:${BASE_IMAGE_TAG}" as base
# Use reproducible build debian image: go/anthos-baremetal-debian-base-image.
FROM gcr.io/anthos-baremetal-staging/debian-cloud-rapture-base/debian-cloud-rapture-base:202403051714@sha256:406b873cf76b6be4cadc02fff80fe9a93738d2604b6e1902d01481113099cbfc as runner

ARG CILIUM_IMAGE_REGISTRY="gcr.io/gke-networking-test-images"
ARG CILIUM_IMAGE_TAG="nightly"
ARG CILIUM_OPERATOR_IMAGE_TAG="nightly"

COPY --from=base cilium.yaml.template cilium-operator.yaml.template ./
RUN sed -i 's|image: \"gcr.io\/gke-networking-test-images\/cilium\/cilium:.*\"|image: \"'${CILIUM_IMAGE_REGISTRY}/cilium/cilium:${CILIUM_IMAGE_TAG}'\"|' cilium.yaml.template && \
    sed -i 's|image: \"gcr.io\/gke-networking-test-images\/cilium\/operator:.*\"|image: \"'${CILIUM_IMAGE_REGISTRY}/cilium/operator-generic:${CILIUM_OPERATOR_IMAGE_TAG}'\"|' cilium-operator.yaml.template

FROM "${BASE_IMAGE_REGISTRY}/${BASE_IMAGE_NAME}:${BASE_IMAGE_TAG}"
COPY --from=runner cilium.yaml.template cilium-operator.yaml.template ./
