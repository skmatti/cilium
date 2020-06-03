************
YAML Upgrade
************

To Generate a Base Config for GKE
=================================

Generate a base configuration:

helm template cilium cilium/cilium --version 1.7.4 \
  --namespace kube-system \
  --set global.autoDirectNodeRoutes=false \
  --set global.cni.chainingMode='generic-veth' \
  --set global.cni.customConf=true \
  --set global.externalIPs.enabled=true \
  --set global.hostServices.enabled=true \
  --set global.installIptablesRules=true \
  --set global.masquerade=true \
  --set global.nodePort.enabled=true \
  --set global.remoteNodeIdentity=true \
  --set global.tunnel='disabled' \
  --set global.wellKnownIdentities.enabled=false \
  > base.yaml

Diff against `google3/cloud/kubernetes/distro/components/advanceddatapath/cilium.yaml`

add settings:
  ALL -> metadata -> labels -> addonmanager.kubernetes.io/mode: Reconcile
  ConfigMap -> cilium-config -> data -> container-runtime: none
  DaemonSet -> cilium -> metadata -> labels -> k8s-app: cilium
  Deployment -> cilium-operator -> metadata -> labels -> io.cilium/app: operator
  Deployment -> cilium-operator -> metadata -> labels -> name: cilium-operator
  Deployment -> cilium-operator -> spec -> template -> spec -> priorityClassName -> system-cluster-critical

del settings:
  AWS related settings
  DaemonSet -> cilium -> spec -> template -> metadata -> annotations
  Deployment -> cilium-operator -> spec -> template -> metadata -> annotations
  --synchronize-k8s-nodes=true

replace settings:
  docker.io <-> {{.AddonsImageRegistry}}
  /opt/cni/bin <-> /home/kubernetes/bin
