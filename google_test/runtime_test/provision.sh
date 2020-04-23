#!/bin/bash

# Copyright 2020 Google LLC

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

# This script, consumed by a Dockerfile, contains necessary components for a
# Prow job to launch Runtime Tests (ginkgo --focus="Runtime*"). It installs
# vagrant, go, and gcloud sdk on the docker image.

export DEBIAN_FRONTEND=noninteractive

export CLOUDSDK_CORE_DISABLE_PROMPTS=1

apt-get update

apt-get install -y apt-utils curl gcc git make python3 rsync tzdata vim

# vagrant

curl -O https://releases.hashicorp.com/vagrant/2.2.7/vagrant_2.2.7_x86_64.deb
apt-get install -y ./vagrant_2.2.7_x86_64.deb

vagrant plugin install vagrant-google vagrant-scp

# go

VERSION=1.14.1
OS=linux
ARCH=amd64
GO_TAR=go$VERSION.$OS-$ARCH.tar.gz

curl -O https://dl.google.com/go/$GO_TAR
tar -C /usr/local -xzf $GO_TAR

go get -u github.com/onsi/ginkgo/ginkgo
go get -u github.com/onsi/gomega

# gcloud

curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/google-cloud-sdk.tar.gz && \
  tar xzf google-cloud-sdk.tar.gz -C / && \
  /google-cloud-sdk/install.sh \
  --disable-installation-options \
  --bash-completion=false \
  --path-update=false \
  --usage-reporting=false && \
  gcloud components install alpha beta kubectl
