# See Makefile for defaults.
ARG BASE_IMAGE_REGISTRY
ARG BASE_IMAGE_NAME
ARG BASE_IMAGE_TAG

FROM "${BASE_IMAGE_REGISTRY}/${BASE_IMAGE_NAME}:${BASE_IMAGE_TAG}" AS base
# Use reproducible build debian image: go/anthos-baremetal-debian-base-image.
FROM gcr.io/anthos-baremetal-staging/debian-cloud-rapture-base/debian-cloud-rapture-base:202403051714@sha256:406b873cf76b6be4cadc02fff80fe9a93738d2604b6e1902d01481113099cbfc AS runner

ARG CILIUM_IMAGE_REGISTRY="gcr.io/gke-networking-test-images"
ARG CILIUM_IMAGE_TAG="nightly"
ARG CILIUM_OPERATOR_IMAGE_TAG="nightly"

COPY --from=base cilium.yaml.template .
RUN sed -i 's|image: \"{{.AddonsImageRegistry}}\/cilium\/cilium:.*\"|image: \"'${CILIUM_IMAGE_REGISTRY}/cilium/cilium:${CILIUM_IMAGE_TAG}'\"|' cilium.yaml.template
COPY --from=base cilium-operator.yaml.template .
RUN sed -i 's|image: \"{{.KCPAddonsImageRegistry}}\/cilium\/operator:.*\"|image: \"'${CILIUM_IMAGE_REGISTRY}/cilium/operator-generic:${CILIUM_OPERATOR_IMAGE_TAG}'\"|' cilium-operator.yaml.template

FROM "${BASE_IMAGE_REGISTRY}/${BASE_IMAGE_NAME}:${BASE_IMAGE_TAG}"
COPY --from=runner cilium.yaml.template .
COPY --from=runner cilium-operator.yaml.template .
