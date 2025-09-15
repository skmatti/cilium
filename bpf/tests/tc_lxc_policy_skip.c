// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

// Define the IP address representing the node itself.
#define LXC_IPV4 v4_node_one

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header. */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_IPV4

// Define network details for the test packet.
#define CLIENT_IP       v4_pod_one
#define CLIENT_PORT     __bpf_htons(111)

#define SERVER_IP       v4_pod_two
#define SERVER_PORT     __bpf_htons(222)

#define SECCTX_FROM_IPCACHE 1

#define DISABLE_SIP_VERIFICATION
#define ENCAP_IFINDEX 42

/*
 * The following defines enable a specific BPF code path for Google VPC.
 * This setup tests a feature where network policy enforcement is bypassed
 * for traffic to/from KubeVirt pods that use a multi-NIC veth interface.
 */
#define ENABLE_GOOGLE_VPC
#define MULTI_NIC_DEVICE_TYPE EP_DEV_TYPE_INDEX_MULTI_NIC_VETH

// Define MAC addresses for the client and server endpoints.
static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

// Include the main BPF datapath logic from bpf_lxc.c.
#include "bpf_lxc.c"

#include "lib/policy.h"

// Define indexes for the program array map.
#define FROM_CONTAINER 0
#define TO_CONTAINER 1

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(max_entries, 2); // Increased size for both programs.
    __array(values, int());
} entry_call_map __section(".maps") = {
    .values = {
        [FROM_CONTAINER] = &cil_from_container,
        [TO_CONTAINER]   = &cil_to_container,
    },
};

/*
 * policy_skip_pktgen is a helper function to generate a standard TCP/IPv4 packet
 * between the client and server pods. It is reused by both the ingress and
 * egress policy skip tests.
 */
static __always_inline int
policy_skip_pktgen(struct __ctx_buff *ctx)
{
    struct pktgen builder;
    struct tcphdr *l4;
    struct ethhdr *l2;
    struct iphdr *l3;
    void *data;

    pktgen__init(&builder, ctx);

    l2 = pktgen__push_ethhdr(&builder);
    if (!l2)
        return TEST_ERROR;
    ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)server_mac);

    l3 = pktgen__push_default_iphdr(&builder);
    if (!l3)
        return TEST_ERROR;
    l3->saddr = CLIENT_IP;
    l3->daddr = SERVER_IP;

    l4 = pktgen__push_default_tcphdr(&builder);
    if (!l4)
        return TEST_ERROR;
    l4->source = CLIENT_PORT;
    l4->dest = SERVER_PORT;

    data = pktgen__push_data(&builder, default_data, sizeof(default_data));
    if (!data)
        return TEST_ERROR;

    pktgen__finish(&builder);

    return 0;
}

/*
 * Test EGRESS policy skip for KubeVirt Pods.
 *
 * This test verifies that egress network policies are bypassed for traffic
 * originating from a multi-NIC KubeVirt pod. The trigger for this bypass is
 * that the packet's source IP does not match the node's own IP (LXC_IPV4).
 */
PKTGEN("tc", "tc_lxc_egress_policy_skip")
int tc_lxc_egress_policy_skip_pktgen(struct __ctx_buff *ctx)
{
    return policy_skip_pktgen(ctx);
}

SETUP("tc", "tc_lxc_egress_policy_skip")
int tc_lxc_egress_policy_skip__setup(struct __ctx_buff *ctx)
{
    policy_add_egress_deny_all_entry();

    /* Jump into the entrypoint */
    tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

    /* Fail if we didn't jump */
    return TEST_ERROR;
}

CHECK("tc", "tc_lxc_egress_policy_skip")
int tc_lxc_egress_policy_skip_check(const struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u32 *status_code;

    test_init();

    data = (void *)(long)ctx_data(ctx);
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");

    status_code = data;
    /*
     * Verify the egress policy was skipped.
     * The packet should NOT be dropped, even with a deny policy, because the
     * source IP (CLIENT_IP) differs from the node IP (LXC_IPV4), which
     * triggers the policy bypass logic for multi-NIC KubeVirt endpoints.
     */

    assert(*status_code != CTX_ACT_DROP);

    test_finish();
}

/*
 * Test INGRESS policy skip for KubeVirt Pods.
 *
 * This test verifies that ingress network policies are bypassed for traffic
 * destined for a multi-NIC KubeVirt pod. This ensures symmetric behavior
 * with the egress policy bypass.
 */
PKTGEN("tc", "tc_lxc_ingress_policy_skip")
int tc_lxc_ingress_policy_skip_pktgen(struct __ctx_buff *ctx)
{
    return policy_skip_pktgen(ctx);
}

SETUP("tc", "tc_lxc_ingress_policy_skip")
int tc_lxc_ingress_policy_skip__setup(struct __ctx_buff *ctx)
{
    /* Jump into the entrypoint */
    tail_call_static(ctx, entry_call_map, TO_CONTAINER);

    /* Fail if we didn't jump */
    return TEST_ERROR;
}

CHECK("tc", "tc_lxc_ingress_policy_skip")
int tc_lxc_ingress_policy_skip_check(const struct __ctx_buff *ctx)
{
    void *data, *data_end;
    __u32 *status_code;

    test_init();

    data = (void *)(long)ctx_data(ctx);
    data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(__u32) > data_end)
        test_fatal("status code out of bounds");

    status_code = data;
    /*
     * Verify the ingress policy was skipped.
     * The packet should NOT be dropped because it is destined for an endpoint
     * identified as a multi-NIC KubeVirt pod, which triggers the ingress
     * policy bypass logic.
     */
    assert(*status_code != CTX_ACT_DROP);

    test_finish();
}
