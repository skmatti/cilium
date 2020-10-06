#!/bin/bash

# This script:
#  1. Compiles local version of Cilium.
#  2. Pushes the binary to the target devbox.
#  3. Starts new cilium binary on the target devbox.

INSTANCE=$1

# Echo all the commands.
set -x

cd ..
make
gcloud compute ssh $INSTANCE --command "killall cilium-agent"
gcloud compute scp ./daemon/cilium-agent $INSTANCE:~/
gcloud compute ssh $INSTANCE --command "\
	sudo ./cilium-agent --identity-allocation-mode=crd --debug=true \
	--enable-ipv4=true --enable-ipv6=false --disable-envoy-version-check=true \
	--tunnel=disabled --k8s-kubeconfig-path=/home/$USER/.kube/config \
	--kube-proxy-replacement=strict --native-routing-cidr=10.217.0.0/16 \
	--enable-bpf-masquerade=true  --debug-verbose=datapath --preallocate-bpf-maps=true \
	> cilium-agent.stdout 2> cilium-agent.stderr < /dev/null &"
