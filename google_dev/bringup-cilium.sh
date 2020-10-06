#!/bin/bash

# This script needs to be executed in cilium/google_dev directory.

# Echo all the commands.
set -x

cd ..
sudo make
sudo make install

sudo nohup ./operator/cilium-operator \
	--k8s-kubeconfig-path=/home/$USER/.kube/config \
	--cluster-pool-ipv4-cidr=10.154.0.0/16 > \
	cilium-operator.stdout 2> cilium-operator.stderr < /dev/null &
