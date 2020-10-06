#!/bin/bash

# This file is used by packer template gcilium-devbox-packer.json to install
# the necessary packges into a new devbox image.

# Echo all the commands.
set -x

# --- Install docker. ---
# Docker preconditions.
sudo apt-get update
sudo apt-get -y -q install dialog apt-utils
sudo apt-get -y -q install \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common
# Docker cert.
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
# Docker repo.
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
# Actual docker.
sudo apt-get update
sudo apt-get -y -q install docker-ce docker-ce-cli containerd.io

# --- Install kubernetes tools. ---
# K8s preconditions.
sudo apt-get update && sudo apt-get install -y -q apt-transport-https curl
# K8s key.
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
# K8s repo.
cat <<EOF | sudo tee /etc/apt/sources.list.d/kubernetes.list
deb https://apt.kubernetes.io/ kubernetes-xenial main
EOF
sudo apt-get update
# Actual K8s.
sudo apt-get install -y -q kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
# --- Start ---
sudo modprobe br_netfilter
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward=1
EOF
sudo sysctl --system

echo $?

# General utilities.
sudo apt-get -y -q install net-tools
sudo apt-get -y -q install locate

# Cilium dependencies
sudo apt-get -y -q install clang
sudo apt-get -y -q install llvm
sudo apt-get -y -q install linux-tools-5.4.0-1024-gcp
sudo apt-get -y -q install linux-cloud-tools-5.4.0-1025-gcp
sudo apt-get -y -q install make
sudo apt-get -y -q install golang
sudo apt-get -y -q install linux-generic
sudo apt-get -y -q install libelf-dev
sudo apt-get -y -q install bison
sudo apt-get -y -q install flex

git clone https://github.com/cilium/iproute2.git && cd iproute2 && make
sudo mv /usr/sbin/tc /usr/sbin/tc-old
sudo cp tc/tc /usr/sbin/
