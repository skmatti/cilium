# Copyright 2023 Google LLC

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

# This Dockerfile assembles an image containing minimal components to
# launch ebpf unit and complexity tests in the test VM.

ARG GOLANG_IMAGE
FROM $GOLANG_IMAGE as golang-dist

FROM gke.gcr.io/debian-base:buster-v1.2.0

# Install dependencies
RUN apt-get -qq update && apt-get install -qq --no-install-recommends \
    apt-transport-https \
    autoconf \
    automake \
    bash \
    build-essential \
    ca-certificates \
    cmake \
    coreutils \
    dpkg-dev \
    file \
    git \
    gnupg2 \
    libc6-dev \
    make \
    patch \
    sudo \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install LLVM
RUN echo "deb https://apt.llvm.org/buster llvm-toolchain-buster-10 main" \
    > /etc/apt/sources.list.d/llvm.list \
    && wget -qO /etc/apt/trusted.gpg.d/llvm.asc \
    https://apt.llvm.org/llvm-snapshot.gpg.key \
    && apt-get -qq update && apt-get install -qq \
    -t llvm-toolchain-buster-10 \
    clang-10 \
    clang-format-10 \
    clang-tidy-10 \
    && for f in /usr/lib/llvm-10/bin/*; do ln -sf "$f" /usr/bin; done \
    && rm -rf /var/lib/apt/lists/*

# Install golang
COPY --from=golang-dist /usr/local/go/ /usr/local/go/
ENV PATH=${PATH}:/usr/local/go/bin:/root/go/bin

# Install go-junit-report, this is a tool that converts go test output to a Junit
# compatible XML report
RUN go install github.com/jstemmer/go-junit-report/v2@latest
