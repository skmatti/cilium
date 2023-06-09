# syntax=docker/dockerfile:1.2

# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

ARG TESTER_IMAGE=quay.io/cilium/image-tester:c37f768323abfba87c90cd9c82d37136183457bc@sha256:4c9d640b6379eb4964b8590acc95ca2dfaa71df70f4467fb7d8ac076acf6a8e1
ARG GOLANG_IMAGE=docker.io/library/golang:1.20.5@sha256:6b3fa4b908676231b50acbbc00e84d8cee9c6ce072b1175c0ff352c57d8a612f
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:22.04@sha256:26c68657ccce2cb0a31b330cb0be2b5e108d467f641c62e13ab40cbec258c68d

ARG CILIUM_LLVM_IMAGE=quay.io/cilium/cilium-llvm:a8c542efc076b62ba683e7699c0013adb6955f0f@sha256:38e8941107bd19eb30bdde6e478760a22325f38d1f2771dfd1b9af81d74235e7
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:78448c1a37ff2b790d5e25c3d8b8ec3e96e6405f@sha256:99a9453a921a8de99899ef82e0822f0c03f65d97005c064e231c06247ad8597d
ARG CILIUM_IPROUTE2_IMAGE=quay.io/cilium/cilium-iproute2:3570d58349efb2d6b0342369a836998c93afd291@sha256:1abcd7a5d2117190ab2690a163ee9cd135bc9e4cf8a4df662a8f993044c79342
ARG CILIUM_IPTABLES_IMAGE=quay.io/cilium/iptables-20.04:e6f83206c57e606282056903ffd3aab0183bdaed@sha256:7ce0de449d356a5259021dc13f2b00a8bddfbea57a1c91ff8f146d455cace9e5

FROM ${CILIUM_LLVM_IMAGE} as llvm-dist
FROM ${CILIUM_BPFTOOL_IMAGE} as bpftool-dist
FROM ${CILIUM_IPROUTE2_IMAGE} as iproute2-dist
FROM ${CILIUM_IPTABLES_IMAGE} as iptables-dist

FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as gops-cni-builder

RUN apt-get update && apt-get install -y binutils-aarch64-linux-gnu binutils-x86-64-linux-gnu

# build-gops.sh will build both archs at the same time
WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    ./build-gops.sh
# download-cni.sh will build both archs at the same time
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime --mount=target=/root/.cache,type=cache --mount=target=/go/pkg/mod,type=cache \
    ./download-cni.sh

FROM ${UBUNTU_IMAGE} as rootfs

# Change the number to force the generation of a new git-tree SHA. Useful when
# we want to re-run 'apt-get upgrade' for stale images.
ENV FORCE_BUILD=6

# Update ubuntu packages to the most recent versions
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y jq

WORKDIR /go/src/github.com/cilium/cilium/images/runtime
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    ./install-runtime-deps.sh

COPY --from=iptables-dist /iptables /iptables
RUN dpkg -i /iptables/*\.deb && rm -rf /iptables

RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium/images/runtime \
    ./iptables-wrapper-installer.sh --no-sanity-check

COPY --from=llvm-dist /usr/local/bin/clang /usr/local/bin/llc /usr/local/bin/
COPY --from=bpftool-dist /usr/local /usr/local
COPY --from=iproute2-dist /usr/lib/libbpf* /usr/lib
COPY --from=iproute2-dist /usr/local /usr/local

ARG TARGETPLATFORM
COPY --from=gops-cni-builder /out/${TARGETPLATFORM}/bin/loopback /cni/loopback
COPY --from=gops-cni-builder /out/${TARGETPLATFORM}/bin/gops /bin/gops

FROM ${TESTER_IMAGE} as test
COPY --from=rootfs / /
COPY --from=llvm-dist /test /test
COPY --from=bpftool-dist /test /test
COPY --from=iproute2-dist /test /test
RUN /test/bin/cst -C /test/llvm
RUN /test/bin/cst -C /test/bpftool
RUN /test/bin/cst -C /test/iproute2

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=rootfs / /
