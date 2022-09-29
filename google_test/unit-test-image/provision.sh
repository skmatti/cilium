#!/bin/bash

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script installs dependencies Cilium needs to run unit tests,
# including clang, llvm, make, go, docker, tc, and bpftool.

set -e -x

export 'IPROUTE_BRANCH'=${IPROUTE_BRANCH:-"libbpf-static-data"}
export 'IPROUTE_GIT'=${IPROUTE_GIT:-https://github.com/cilium/iproute2}
export 'LIBBPF_GIT'=${LIBBPF_GIT:-https://github.com/cilium/libbpf}

export GOPATH=/go
export GOROOT=/usr/local/go

export PATH=$GOROOT/bin:$GOPATH/bin:$GOPATH/src/github.com/cilium/cilium/bpf:/sbin:$PATH

export DEBIAN_FRONTEND=noninteractive

ENV_VAR_PATH=/etc/profile.d/env.sh

WORKING_DIR=/working-dir

sudo mkdir -p $WORKING_DIR
sudo chmod 777 $WORKING_DIR

sudo mkdir -p $GOPATH
sudo chmod 777 $GOPATH

cd $WORKING_DIR

# build dependencies

sudo apt-get update
sudo apt-get upgrade -y --no-install-recommends

sudo apt-get install -y --no-install-recommends \
  apt-utils \
  binutils \
  bison \
  build-essential \
  ca-certificates \
  coreutils \
  curl \
  flex \
  gcc \
  git \
  iproute2 \
  libc6-dev \
  libc6-dev-i386 \
  libelf-dev \
  libmnl-dev \
  m4 \
  make \
  pkg-config \
  python3 \
  rsync \
  unzip \
  wget \
  xz-utils \
  zip \
  zlib1g-dev

# clang/llvm

sudo apt-get install -y --no-install-recommends \
  gnupg \
  lsb-release \
  software-properties-common

sudo apt-get update

wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 11

sudo mv /usr/bin/readelf /usr/bin/readelf_old

sudo ln -s /usr/bin/clang-11 /usr/bin/clang
sudo ln -s /usr/bin/clang++-11 /usr/bin/clang++
sudo ln -s /usr/lib/llvm-11/bin/llc /usr/bin/llc
sudo ln -s /usr/lib/llvm-11/bin/llvm-readelf /usr/bin/readelf

# go

VERSION=1.19
OS=linux
ARCH=amd64
GO_TAR=go$VERSION.$OS-$ARCH.tar.gz

curl -O https://dl.google.com/go/$GO_TAR
sudo tar -C /usr/local -xzf $GO_TAR

go install github.com/gordonklaus/ineffassign@latest

# docker

sudo dpkg --remove docker docker-engine docker.io containerd runc

sudo apt-get install -y \
  apt-transport-https \
  ca-certificates \
  curl \
  gnupg-agent \
  software-properties-common

curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -

sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"

sudo apt-get update

sudo apt-get install -y docker-ce docker-ce-cli containerd.io

sudo getent group docker || sudo groupadd docker
sudo usermod -aG docker $USER

# bpftool

git clone --depth 1 -b master git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git linux
cd linux/tools/bpf/bpftool
make -j `getconf _NPROCESSORS_ONLN`
strip bpftool
cd $WORKING_DIR
cp  linux/tools/bpf/bpftool/bpftool $GOPATH/bin/bpftool

# libbpf and iproute2 build sould be kept close to:
# https://github.com/cilium/packer-ci-build/blob/d1841cb1162ae91efbae11d5b9709ed880fdcc9c/provision/ubuntu/install.sh#L129

# libbpf and iproute2
cd /tmp
git clone --depth=1 ${LIBBPF_GIT}
cd /tmp/libbpf/src
make -j "$(getconf _NPROCESSORS_ONLN)"
# By default, libbpf.so is installed to /usr/lib64 which isn't in LD_LIBRARY_PATH on Ubuntu.
# Overriding LIBDIR in addition to setting PREFIX seems to be needed due to the structure of
# libbpf's Makefile.
sudo PREFIX="/usr" LIBDIR="/usr/lib/x86_64-linux-gnu" make install
sudo ldconfig

cd /tmp
git clone -b ${IPROUTE_BRANCH} ${IPROUTE_GIT}
cd /tmp/iproute2
LIBBPF_FORCE="on" \
PKG_CONFIG_PATH="/usr/lib64/pkgconfig"  \
PKG_CONFIG="pkg-config --define-prefix" \
./configure
make -j `getconf _NPROCESSORS_ONLN`
cp tc/tc $GOPATH/bin/tc
sudo make install
rm -rf /tmp/iproute2


# set env

sudo chmod 777 -R $GOPATH

sudo chmod 777 /etc/profile.d

echo "export GOPATH=$GOPATH" >> $ENV_VAR_PATH
echo "export GOROOT=$GOROOT" >> $ENV_VAR_PATH

echo "export PATH=$PATH" >> $ENV_VAR_PATH

# cleanups

cd /

sudo apt-get clean -y
sudo apt-get autoremove -y

sudo rm -rf $WORKING_DIR /tmp/* /var/lib/apt/lists/* /var/tmp/*
