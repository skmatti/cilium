#!/bin/bash

set -euxo pipefail
shopt -s inherit_errexit

function remote_execution_from_gce_bootstrapper {
  local cmd="${1:?}"
  for resource_directory in "${ARTIFACTS:?}/.kubetest2-tailorbird"/*; do
    host_machine_connectivity_info_dir=${resource_directory}/connectivity-metadata
    connectivity_metadata_file="${host_machine_connectivity_info_dir}/connectivity_metadata.json"
    if [[ -d "${host_machine_connectivity_info_dir}" && -f "${connectivity_metadata_file}" ]];  then
      bootstrapper_IP=$(grep -Po '"bastion_hostname":.*?[^\\]"' "${connectivity_metadata_file}" | cut -d':' -f2 | tr -d '"')
      ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -i "${host_machine_connectivity_info_dir}/id_rsa" root@"${bootstrapper_IP}" "${cmd}"
    fi
  done
}
