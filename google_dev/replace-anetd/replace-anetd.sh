#!/bin/bash

set -x

BASEDIR=$(dirname $(realpath $0))

clone_configmap () {
  CM_NAME=$1
  MODIFIED_CM_NAME="${CM_NAME}-modified"

  CONFIGMAP=`kubectl -n kube-system get cm "${CM_NAME}" -o json`

  if [ "0" == "$?" ] ; then
    echo $CONFIGMAP | tee "${CM_NAME}-orig.json" \
      | jq -f "${BASEDIR}/modifyCiliumConfig.jq" --arg newName "${MODIFIED_CM_NAME}" > "${MODIFIED_CM_NAME}.json"
    kubectl delete -n kube-system cm "${MODIFIED_CM_NAME}"
    kubectl apply -f "${MODIFIED_CM_NAME}.json"
  else
    1>&2 echo "ConfigMap '${CM_NAME}' not found"
  fi
}

clone_anetd_ds() {
  kubectl -n kube-system get ds anetd -o json \
    | tee anetd-orig.json \
    | jq -f $BASEDIR/modifyAnetd.jq \
    | jq -f $BASEDIR/modifyAnetdSingleCm.jq \
    | jq -f $BASEDIR/modifyAnetdProjectedCms.jq > anetd-modified.json

  kubectl delete -n kube-system ds anetd-modified
  kubectl apply -f anetd-modified.json
}

disable_orig_anetd_ds() {
  patch='
  spec:
    template:
      spec:
        nodeSelector:
          networking.gke.io/select-nothing: "dev-only"
  '

  kubectl patch -n kube-system ds anetd -p "$patch"
}

clone_configmap cilium-config
clone_configmap cilium-hubble-config

clone_anetd_ds
disable_orig_anetd_ds
