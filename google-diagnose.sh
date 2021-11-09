#!/bin/bash -x

# Script to collect cilium health stats for gke snapshot

cilium version
cilium status --verbose
cilium-health status
cilium debuginfo

cilium config
cilium node list
cilium metrics list
cilium identity list
cilium policy selectors -o json

bpftool map show
bpftool prog show
bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_lb4_services_v2
bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_lb4_services
bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_lb4_backends
bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_lb6_services_v2
bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_lb6_services
bpftool map dump pinned /sys/fs/bpf/tc/globals/cilium_lb6_backends

cilium map list --verbose
cilium bpf tunnel list
cilium bpf lb list
cilium bpf endpoint list
cilium bpf ipcache list
cilium bpf sha list
cilium bpf egress list
