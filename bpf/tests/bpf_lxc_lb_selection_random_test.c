// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

/* Set the LXC source address to be the address of pod one */
#define LXC_IPV4 (__be32)v4_pod_one

/* Enable CT debug output */
#undef QUIET_CT

#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test*/
#define ENABLE_IPV4

/* import node_config.h to define all the LB_SELECTION options */
#include <node_config.h>

/* redefine LB_SELECTION as LB_SELECTION_MAGLEV to test if
 * bpf_lxc program is correctly redefining LB_SELECTION to
 * LB_SELECTION_RANDOM
 */
#undef LB_SELECTION
#define LB_SELECTION LB_SELECTION_MAGLEV

#define assert_num_equal(expected_num, result_num)                                \
	({                                                                      \
		if ((expected_num) != (result_num)) {                                 \
			test_log("assert failed at " __FILE__ ":" LINE_STRING); \
			test_error("-- expected: %d  got: %d", (expected_num),     \
				   (result_num))                                   \
		}                                                               \
	})

#define assert_ip_equal(expected_ip, result_ip)                                    \
	({                                                                       \
		if ((expected_ip) != (result_ip)) {                                    \
			__u32 exp1 = ((expected_ip) >> 24) & 0xFF;                  \
			__u32 exp2 = ((expected_ip) >> 16) & 0xFF;                  \
			__u32 exp3 = ((expected_ip) >> 8) & 0xFF;                   \
			__u32 exp4 = ((expected_ip)) & 0xFF;                        \
			__u32 recv1 = ((result_ip) >> 24) & 0xFF;                   \
			__u32 recv2 = ((result_ip) >> 16) & 0xFF;                   \
			__u32 recv3 = ((result_ip) >> 8) & 0xFF;                    \
			__u32 recv4 = ((result_ip)) & 0xFF;                         \
			test_log("line %d: ip address not equal", __LINE__);     \
			test_error("-- expected: %d.%d.%d.%d  got: %d.%d.%d.%d", \
				   exp4, exp3, exp2, exp1, recv4, recv3,         \
				   recv2, recv1);                                \
		}                                                                \
	})

// Mock get_prandom_u32 to make backend selection deterministic.
// We'll store the desired return value in a BPF map.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
} prandom_mock_map __section(".maps");

static __always_inline __u32 mock_get_prandom_u32(void) {
    __u32 key = 0;
    __u32 *val = map_lookup_elem(&prandom_mock_map, &key);
    if (val) {
        return *val;
    }
    return 0; // Default to 0 if not set, though it should be set in setup.
}

#define get_prandom_u32 mock_get_prandom_u32

#include <bpf_lxc.c>
#include "lib/lb.h"
#include "lib/policy.h"

#define CLIENT_IP     v4_ext_one
#define SVC_IP IPV4(172, 16, 0, 1)
#define SVC_PORT bpf_htons(80)
#define BACKEND_IP_1 IPV4(10, 0, 0, 10)
#define BACKEND_PORT_1 bpf_htons(8080)
#define BACKEND_ID_1 101
#define BACKEND_IP_2 IPV4(10, 0, 0, 11)
#define BACKEND_PORT_2 bpf_htons(8081)
#define BACKEND_ID_2 102
#define BACKEND_IP_3 IPV4(10, 0, 0, 12)
#define BACKEND_PORT_3 bpf_htons(8082)
#define BACKEND_ID_3 103

#define FROM_CONTAINER_ENTRY 0
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_CONTAINER_ENTRY] = &cil_from_container,
	},
};

#ifndef SKIP_POLICY_MAP
static __always_inline void add_allow_all_egress_policy(void)
{
	struct policy_key policy_key = {
		.egress = 1, // Egress policy
		.sec_label = 0, // Wildcard security label
		.protocol = 0, // Wildcard protocol
		.dport = 0, // Wildcard destination port
	};
	struct policy_entry policy_value = {
		.deny = 0, // Allow
	};
	map_update_elem(&POLICY_MAP, &policy_key, &policy_value, BPF_ANY);
}
#endif


/* Let backend's ingress path create its CT own entry: */
PKTGEN("tc", "lb4_select_backend_random")
int lb4_select_backend_random_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	/* Ethernet Header */
	struct ethhdr *l2 = pktgen__push_ethhdr(&builder);
	if (!l2) return TEST_ERROR;

	/* IPv4 Header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);
	if (!l3) return TEST_ERROR;
	l3->saddr = CLIENT_IP;
	l3->daddr = SVC_IP;

	/* TCP Header */
	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4) return TEST_ERROR;
	l4->source = bpf_htons(12345);
	l4->dest = SVC_PORT;

	/* Payload */
	void *data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data) return TEST_ERROR;

	pktgen__finish(&builder);
	return 0;
}

SETUP("tc", "lb4_select_backend_random")
int lb4_select_backend_random_setup(struct __ctx_buff *ctx)
{
    __u16 revnat_id = 1;
	// Setup service with 3 backends
	lb_v4_add_service(SVC_IP, SVC_PORT, 3, revnat_id); // count = 3 backends

	lb_v4_add_backend(SVC_IP, SVC_PORT, 1, BACKEND_ID_1, BACKEND_IP_1, BACKEND_PORT_1, IPPROTO_TCP, 0);
	lb_v4_add_backend(SVC_IP, SVC_PORT, 2, BACKEND_ID_2, BACKEND_IP_2, BACKEND_PORT_2, IPPROTO_TCP, 0);
	lb_v4_add_backend(SVC_IP, SVC_PORT, 3, BACKEND_ID_3, BACKEND_IP_3, BACKEND_PORT_3, IPPROTO_TCP, 0);

	/* Mock prandom_u32 to select the second backend (index 1, slot 2)
	 * (get_prandom_u32() % svc->count) + 1
	 * If svc->count is 3, to get slot 2, prandom_u32 should be 1.
	 */
	__u32 prandom_val = 1;
	__u32 key = 0;
	map_update_elem(&prandom_mock_map, &key, &prandom_val, BPF_ANY);

	add_allow_all_egress_policy();

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER_ENTRY);

	return TEST_ERROR;
}

CHECK("tc", "lb4_select_backend_random")
int lb4_select_backend_random_check(__maybe_unused const struct __ctx_buff *ctx)
{
	test_init();

	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	__u32 *status_code = data;

	assert_num_equal(*status_code, CTX_ACT_OK); // Expect OK if redirected to local backend

	struct ethhdr *l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("l2 out of bounds");

	struct iphdr *l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("l3 out of bounds");

	struct tcphdr *l4 = (void *)l3 + sizeof(*l3);
	if ((void *)l4 + sizeof(*l4) > data_end)
		test_fatal("l4 out of bounds");

	// Verify that the packet was redirected to BACKEND_IP_2
	assert_ip_equal(BACKEND_IP_2, l3->daddr);
	assert_num_equal(BACKEND_PORT_2, l4->dest);

	test_finish();
}
