#!/bin/bash
# This script needs to have following environment variables set.
# 1. CILIUM_CONFIG_MAP: path of cilium config map
# 2. MTU_DEVICE_IP: IP address of the interface to pick MTU from
# If CILIUM_CONFIG_MAP is specified, the script will check if mtu config is
# present in the config map at the path 'mtuFilePath'. If mtu
# config is not present, the script will try to get the mtu of the interface
# whose IP address is specified in MTU_DEVICE_IP. It will then invoke
# cilium-agent binary and pass this mtu (if it gets a valid one) as an
# additional argument along with existing arguments passed to the script

set -x
: "FileName: $0"

# Get all arguments passed to this script
args="$@"

if [ "${CILIUM_CONFIG_MAP}" != "" ]; then
    mtuFilePath="${CILIUM_CONFIG_MAP}/mtu"

    if [ ! -f "$mtuFilePath" ]; then
        if [ "${MTU_DEVICE_IP}" != "" ]; then
            # Get mtu of the interface which has ip address '${MTU_DEVICE_IP}'
            mtu=$(ip addr show to ${MTU_DEVICE_IP} | grep mtu | awk '{for (I=1;I<NF;I++) if ($I == "mtu") print $(I+1)}')
            # Check if we could retrive a number in 'mtu'
            if [ "$(echo $mtu | grep -E "^[0-9]+$")" ]; then
                mtuArg="--mtu=$mtu"
            fi
        fi
    fi
fi

/usr/bin/cilium-agent $args $mtuArg

