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

export GOPATH=/go
export GOROOT=/usr/local/go

export PATH=$GOROOT/bin:$GOPATH/bin:$GOPATH/src/github.com/cilium/cilium/bpf:$PATH

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
  clang-7 \
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
  llvm-7 \
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

sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-7 100

sudo update-alternatives --install /usr/bin/llc llc /usr/bin/llc-7 100

# go

VERSION=1.14.1
OS=linux
ARCH=amd64
GO_TAR=go$VERSION.$OS-$ARCH.tar.gz

curl -O https://dl.google.com/go/$GO_TAR
sudo tar -C /usr/local -xzf $GO_TAR

go get -u github.com/gordonklaus/ineffassign

# docker

sudo apt-get purge -y docker docker-engine docker.io containerd runc

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

sudo groupadd docker
sudo usermod -aG docker $USER

# tc

git clone https://github.com/cilium/iproute2.git
cd iproute2
make
cp tc/tc $GOPATH/bin/tc
cd ..

# bpftool

git clone --depth 1 -b master git://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git linux
cd linux/tools/bpf/bpftool
make -j `getconf _NPROCESSORS_ONLN`
strip bpftool
cd $WORKING_DIR
cp  linux/tools/bpf/bpftool/bpftool $GOPATH/bin/bpftool

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
