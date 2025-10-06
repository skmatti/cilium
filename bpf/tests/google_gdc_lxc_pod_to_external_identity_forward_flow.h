/* Regression Test Guarding Connectivity Between Endpoints and Known External Endpoints
 *
 * One way this flow is used for User Clusters of Perimeter Clusters to connect
 * to the clustermesh api servers in a remote zone in GDC-AG.
 *
 * Example bug where this flow was broken b/447189190.
 */

#pragma once

#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* TEST VALUES */
#define ENCAP_IFINDEX 4

#define SRC_NODE_MAC mac_one
#define SRC_POD_MAC mac_two

#define DST_NODE_MAC mac_three

#define SRC_NODE_IP v4_node_one
#define DST_NODE_IP v4_node_two

#define IPV4_DIRECT_ROUTING SRC_NODE_IP

#define SRC_POD_IP v4_pod_one
#define SRC_PORT 5000

#define SRC_POD_IFINDEX 18

#define WORLD_ENDPOINT_IP v4_ext_one
#define WORLD_ENDPOINT_PORT 8080

long mock_fib_lookup(__maybe_unused void *ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen,
		     __maybe_unused __u32 flags)
{
	__bpf_memcpy_builtin(params->smac, (__u8 *)SRC_NODE_MAC, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)DST_NODE_MAC, ETH_ALEN);

	return BPF_FIB_LKUP_RET_SUCCESS;
};

#include "bpf_lxc.c"

#include "lib/google/pktgen.h"
#include "lib/ipcache.h"
#include "lib/endpoint.h"

#define FROM_CONTAINER 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER] = &cil_from_container,
	},
};

#ifndef SKIP_POLICY_MAP
static __always_inline void add_allow_all_egress_policy(void)
{
	struct policy_key policy_key = {
		.egress = 1,
	};
	struct policy_entry policy_value = {
		.deny = 0,
	};
	map_update_elem(&POLICY_MAP, &policy_key, &policy_value, BPF_ANY);
}
#endif

PKTGEN("tc", "google_gdc_lxc_pod_to_external_identity_forward_flow")
int google_gdc_lxc_pod_to_external_identity_forward_flow_pktgen(struct __ctx_buff *ctx __maybe_unused)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	struct ethhdr *l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->protocol = (__u8) IPPROTO_TCP;
	l3->saddr = bpf_htonl(SRC_POD_IP);
	l3->daddr = bpf_htonl(WORLD_ENDPOINT_IP);

	struct tcphdr* l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = bpf_htons(SRC_PORT);
	l4->dest = bpf_htons(WORLD_ENDPOINT_PORT);

	void* data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "google_gdc_lxc_pod_to_external_identity_forward_flow")
int google_gdc_lxc_pod_to_external_identity_forward_flow_setup(struct __ctx_buff* ctx __maybe_unused)
{

	/* Egress allow all policy */
	add_allow_all_egress_policy();

	/* Set Up Src Node */
	ipcache_v4_add_entry(bpf_htonl(SRC_NODE_IP), 0, HOST_ID, 0, 0);

	/* Set Up Src Pod */
	ipcache_v4_add_entry(bpf_htonl(SRC_POD_IP), 0, 112233, bpf_htonl(SRC_NODE_IP), 0);

	endpoint_v4_add_entry(bpf_htonl(SRC_POD_IP), SRC_POD_IFINDEX, 0, 0, 112233,
			      (__u8 *) SRC_POD_MAC, (__u8 *) SRC_NODE_MAC);

	/* Set Up WORLD Endpoint */
	ipcache_v4_add_entry(bpf_htonl(WORLD_ENDPOINT_IP), 0, WORLD_IPV4_ID, 0 /* tunnel ep: 0.0.0.0 */, 0);

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	return TEST_ERROR;
}

CHECK("tc", "google_gdc_lxc_pod_to_external_identity_forward_flow")
int google_gdc_lxc_pod_to_external_identity_forward_flow_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	void* data = (void*)(long) ctx_data(ctx);
	void* data_end = (void*)(long) ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	__u32 *status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_error("expected CTX_ACT_OK ('%d') but got '%d' instead", CTX_ACT_OK, *status_code);

	struct ethhdr* l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	struct iphdr *l3 = (void *)l2 + sizeof(*l2);

	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	struct tcphdr *l4 = (void *)l3 + sizeof(*l3);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	assert_ip_equal(SRC_POD_IP, bpf_ntohl(l3->saddr));
	assert_ip_equal(WORLD_ENDPOINT_IP, bpf_ntohl(l3->daddr));

	assert_num_equal(SRC_PORT, bpf_ntohs(l4->source));
	assert_num_equal(WORLD_ENDPOINT_PORT, bpf_ntohs(l4->dest));

	test_finish();
}
