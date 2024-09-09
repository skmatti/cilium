ARG BASE_IMAGE_REGISTRY="gcr.io/anthos-networking-ci/wora"
ARG BASE_IMAGE_NAME="anthos-networking-test-workloads"
ARG BASE_IMAGE_TAG="latest"

FROM "${BASE_IMAGE_REGISTRY}/${BASE_IMAGE_NAME}:${BASE_IMAGE_TAG}" AS builder

COPY go.mod go.sum e2e_suite_test.go /tmp/src/
COPY verifiers/ /tmp/src/verifiers/
COPY pkg/ /tmp/src/pkg

ARG VENDOR

COPY "${VENDOR}/" /tmp/src/vendor/

RUN cd /tmp/src && \
    go install github.com/onsi/ginkgo/v2/ginkgo && \
    go test -c e2e_suite_test.go && \
    mkdir -p /test && \
    cp $(go env GOPATH)/bin/ginkgo e2e.test /test/

FROM "${BASE_IMAGE_REGISTRY}/${BASE_IMAGE_NAME}:${BASE_IMAGE_TAG}"

COPY --from=builder /test/ /test/
