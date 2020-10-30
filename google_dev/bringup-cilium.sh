#!/bin/bash

# This script needs to be executed in cilium/google_dev directory.

# Echo all the commands.
set -x

cd ..
sudo make
sudo make install

# TODO: Figure out the right values for --cluster-pool-ipv4-cidr and
# --cluster-pool-ipv6-cidr flags.
sudo nohup ./operator/cilium-operator \
	--k8s-kubeconfig-path=/home/$USER/.kube/config \
	--cluster-pool-ipv4-cidr=10.154.0.0/16 \
	--cluster-pool-ipv6-cidr=1::0/110 > \
	cilium-operator.stdout 2> cilium-operator.stderr < /dev/null &
