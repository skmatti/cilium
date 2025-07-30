ARG BASE_IMAGE_REGISTRY="gcr.io/anthos-networking-ci/wora"
ARG BASE_IMAGE_NAME="anthos-networking-test-workloads"
ARG BASE_IMAGE_TAG="latest"

FROM "${BASE_IMAGE_REGISTRY}/${BASE_IMAGE_NAME}:${BASE_IMAGE_TAG}" AS builder

COPY go.mod go.sum e2e_suite_test.go /tmp/src/
COPY verifiers/ /tmp/src/verifiers/
COPY pkg/ /tmp/src/pkg/

ARG VENDOR

COPY "${VENDOR}/" /tmp/src/vendor/

# Build and copy e2e test binary.
RUN cd /tmp/src && \
    go test -c e2e_suite_test.go && \
    mkdir -p /test/e2e/ && \
    cp e2e.test /test/e2e/

# Download and copy ginkgo binary to /test/e2e directory.
RUN cd /tmp/src && \
    go install github.com/onsi/ginkgo/v2/ginkgo && \
    mkdir -p /test/e2e/ && \
    cp $(go env GOPATH)/bin/ginkgo /test/e2e/

# Download and copy kubernetes conformance test binary.
ARG K8S_VERSION="v1.29.2"

RUN mkdir -p "/test/conformance/" && \
    curl -L \
    "https://dl.k8s.io/${K8S_VERSION}/kubernetes-test-linux-amd64.tar.gz" \
    -o "/tmp/kubernetes-test-linux-amd64.tar.gz" && \
    tar -xvzf "/tmp/kubernetes-test-linux-amd64.tar.gz" \
    --directory "/test/conformance/" \
    --strip-components=3 \
    kubernetes/test/bin/ginkgo \
    kubernetes/test/bin/e2e.test && \
    rm "/tmp/kubernetes-test-linux-amd64.tar.gz"

FROM "${BASE_IMAGE_REGISTRY}/${BASE_IMAGE_NAME}:${BASE_IMAGE_TAG}"

COPY --from=builder /test/ /test/
