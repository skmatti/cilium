ARG BASE_IMAGE_REGISTRY="gcr.io/anthos-networking-ci/applications"
ARG BASE_IMAGE_NAME="anthos-networking-test-workloads"
ARG BASE_IMAGE_TAG="latest"

FROM "${BASE_IMAGE_REGISTRY}/${BASE_IMAGE_NAME}:${BASE_IMAGE_TAG}"

ARG K8S_VERSION="v1.29.2"

RUN mkdir -p "/test" && \
    curl -L \
    "https://dl.k8s.io/${K8S_VERSION}/kubernetes-test-linux-amd64.tar.gz" \
    -o "/tmp/kubernetes-test-linux-amd64.tar.gz" && \
    tar -xvzf "/tmp/kubernetes-test-linux-amd64.tar.gz" \
    --directory "/test" \
    --strip-components=3 \
    kubernetes/test/bin/ginkgo \
    kubernetes/test/bin/e2e.test && \
    rm "/tmp/kubernetes-test-linux-amd64.tar.gz"
