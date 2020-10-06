#!/bin/bash

# Echo all the commands.
set -x

sudo kubeadm init --pod-network-cidr=10.217.0.0/16 --skip-phases=addon/kube-proxy
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
kubectl taint nodes --all node-role.kubernetes.io/master-
sudo systemctl daemon-reload
sudo systemctl restart kubelet
