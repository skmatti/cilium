************
YAML Upgrade
************

To Generate a Base Config for GKE
=================================

Generate a base configuration:

helm template cilium cilium/cilium --version 1.8.0 \
--namespace kube-system \
--set global.cni.binPath=/home/kubernetes/bin \
--set global.gke.enabled=true \
--set global.autoDirectNodeRoutes=false \
--set global.cni.chainingMode='generic-veth' \
--set global.cni.customConf=true \
--set global.externalIPs.enabled=true \
--set global.hostServices.enabled=true \
--set global.installIptablesRules=true \
--set global.masquerade=false \
--set global.nodePort.enabled=true \
--set global.remoteNodeIdentity=true \
--set global.tunnel='disabled' \
--set global.wellKnownIdentities.enabled=false \
--set --set global.prometheus.enabled=true \
--set global.operatorPrometheus.enabled=true > base.yaml

Diff against `google3/cloud/kubernetes/distro/components/advanceddatapath/cilium.yaml`
