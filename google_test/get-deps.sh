#!/bin/bash

# This scripts is triggered by `unit-test-local.sh`.
#
# This gets the rquired deps to run Cilium's tests and will be
# removed once we have all deps baked in the testing image.

set -xe

export GOROOT=/usr/local/go
export GOPATH=/go
export PATH=$GOROOT/bin:$GOPATH/bin:$GOPATH/src/github.com/cilium/cilium/bpf:$PATH
export GO_VERSION=1.14.1

# Fetch Cilium build deps.
apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends apt-utils binutils ca-certificates clang-7 coreutils curl gcc git libc6-dev libc6-dev-i386 libelf-dev llvm-7 m4 make pkg-config python rsync unzip wget zip zlib1g-dev bison flex && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-7 100 && update-alternatives --install /usr/bin/llc llc /usr/bin/llc-7 100

# Fetch golang.
curl -sfL https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz | tar -xzC /usr/local && \
  GO111MODULE=on go get github.com/gordonklaus/ineffassign@1003c8bd00dc2869cb5ca5282e6ce33834fed514 && \
  go clean -cache -modcache

# Fetch docker deps and docker-ce.
apt-get update && apt-get install -y --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg2 \
    software-properties-common \
    lsb-release && \
    rm -rf /var/lib/apt/lists/*

curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo "$ID")/gpg \
    | apt-key add - && \
    add-apt-repository \
    "deb [arch=amd64] https://download.docker.com/linux/$(. /etc/os-release; echo "$ID") \
    $(lsb_release -cs) stable"

apt-get update && \
    apt-get install -y --no-install-recommends docker-ce=5:19.03.* && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's/cgroupfs_mount$/#cgroupfs_mount\n/' /etc/init.d/docker \
    && update-alternatives --set iptables /usr/sbin/iptables-legacy \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# Fetch tc with rquired patch.
git clone https://github.com/cilium/iproute2.git && \
cd iproute2 && make && \
cp tc/tc $GOPATH/bin/tc && \
cd ..

# Fetch bpftool.
git clone --depth 1 -b master git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git linux && \
cd linux/tools/bpf/bpftool/ && \
make -j `getconf _NPROCESSORS_ONLN` && \
strip bpftool && \
cd ../../../../

cp linux/tools/bpf/bpftool/bpftool $GOPATH/bin/bpftool
