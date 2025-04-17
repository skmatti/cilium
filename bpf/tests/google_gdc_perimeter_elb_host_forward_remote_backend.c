#include "common.h"

#include <bpf/ctx/skb.h>
#include "lib/endian.h"
#include "pktgen.h"

#define ETH_HLEN 14
#define HAVE_LPM_TRIE_MAP_TYPE
#define NOT_VTEP_DST 0

/* FLAGS UNDER TEST */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_GOOGLE_GENEVE
#define ENCAP_IFINDEX 4
#define ENABLE_GOOGLE_VPC
#define ENABLE_HOST_FIREWALL

/* TURNS ON PERIMETER ELB */
#define ENABLE_EGRESS_GATEWAY_REDIRECT

/* Skip ingress policy checks, not needed to validate hairpin flow */
#define USE_BPF_PROG_FOR_INGRESS_POLICY

#define ENABLE_EGRESS_GATEWAY
#define ENABLE_EGRESS_GATEWAY_COMMON

/* SITUATION PACKET INFO */
#define SRC_NODE_MAC   mac_one
#define DST_NODE_MAC   mac_two

#define SRC_INFRA_NODE v4_node_one
#define DST_INFRA_NODE v4_node_two

/* Needed to determine if the packet should be decapped */
#define IPV4_DIRECT_ROUTING DST_INFRA_NODE

#define SOURCE_PERIMETER_NODE v4_pod_two

/* used to look up which perimeter node it came from */
#define SOURCE_PERIMETER_NODE_REV_NAT_ID 44

#define GENEVE_SRC_PORT 6081

/*
 * Needed to determine if the packet should be decapped;
 * 8472 is the value ofTUNNEL_PORT
 */
#define GENEVE_DST_PORT 8472

#define CLIENT_IP     v4_ext_one
#define BACKEND_IP    v4_pod_one

#define CLIENT_PORT   4444
#define BACKEND_PORT  80

#define DEST_IF_INDEX 10
#define DEST_IF_ID    200

/* TEST SET UP */

#include "bpf_host.c"

#include "lib/encap.h"
#include "../lib/google/geneve.h"
#include "lib/lb.h"

#include "lib/ipcache.h"
#include "lib/policy.h"

#define FROM_NETDEV 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
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

#undef ctx_redirect
#define ctx_redirect mock_ctx_redirect

#include "lib/google/pktgen.h"

static __always_inline __maybe_unused int mock_ctx_redirect(struct __sk_buff *ctx,
							    int ifindex __maybe_unused,
							    __u32 flags __maybe_unused)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4;

	cilium_dbg(ctx, DBG_GENERIC, 999, __LINE__);

	ip4 = data + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return CTX_ACT_DROP;

	/* Forward to backend: */
	if (ip4->saddr == CLIENT_IP && ifindex == DEST_IF_INDEX) {
		ctx_store_meta(ctx, CB_IFINDEX, ifindex);
		return CTX_ACT_REDIRECT;
	}

	return CTX_ACT_DROP;
}

PKTGEN("tc", "elb_infra_traffic_forward_direction")
int elb_infra_traffic_forward_direction_pktgen(struct __ctx_buff *ctx __maybe_unused)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	struct google_pktgen__genevehdr_params geneve_params = {
		.src_mac = (__u8 *)SRC_NODE_MAC,
		.dst_mac = (__u8 *)DST_NODE_MAC,

		.outer_src_ip = SRC_INFRA_NODE,
		.outer_dst_ip = DST_INFRA_NODE,

		.outer_src_port = GENEVE_SRC_PORT,
		.outer_dst_port = GENEVE_DST_PORT,

		.direction = GENEVE_INGRESS_CLUSTER,

		.perimeter_node = SOURCE_PERIMETER_NODE,
	};

	int ret = google_pktgen__push_genevehdr(&builder, geneve_params);

	if (ret != TEST_PASS)
		return ret;

	/* IPv4 Header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = BACKEND_IP;
	l3->protocol = IPPROTO_TCP;

	/* TCP Header */
	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = bpf_htons(CLIENT_PORT);
	l4->dest = bpf_htons(BACKEND_PORT);

	/* Packet Data */
	void *data =
		pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	google_pktgen__finish_geneve_pkt(&builder);

	return TEST_PASS;
}

SETUP("tc", "elb_infra_traffic_forward_direction")
int elb_infra_traffic_forward_direction_setup(struct __ctx_buff *ctx)
{
	add_allow_all_egress_policy();

	/* IP Cache */
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};

	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = DST_INFRA_NODE,
		.flag_skip_tunnel = false,
	};

	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* Add Backend IP to Local Endpoints Map */
	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};

	struct endpoint_info ep_value = {
		.ifindex = DEST_IF_INDEX,
		.lxc_id = DEST_IF_ID,
	};

	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	/* Set up perimete node maps */
	struct ipv4_redirect_ep redirect_ep_key = {
		.ip4 = SOURCE_PERIMETER_NODE,
	};

	__u16 endpoint_id = SOURCE_PERIMETER_NODE_REV_NAT_ID;

	map_update_elem(&GOOGLE_REDIRECT_EP_ID_V4_MAP, &redirect_ep_key,
			&endpoint_id, BPF_ANY);
	map_update_elem(&GOOGLE_REDIRECT_EP_IP_V4_MAP, &endpoint_id,
			&redirect_ep_key, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	return TEST_ERROR;
}

CHECK("tc", "elb_infra_traffic_forward_direction")
int elb_infra_traffic_forward_direction_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	__u32 status_code = *(__u32 *)data;

	if (status_code != CTX_ACT_REDIRECT)
		test_error("expected status code to be CTX_ACT_REDIRECT ('%d') but got '%d'",
			   CTX_ACT_REDIRECT, status_code);

	struct ethhdr *l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	struct iphdr *l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	struct tcphdr *l4 = (void *)l3 + sizeof(struct tcphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	assert_ip_equal(CLIENT_IP, l3->saddr);
	assert_ip_equal(BACKEND_IP, l3->daddr);

	/* Inspect Connection Tracking for correct rev_nat_id is saved */
	struct ipv4_ct_tuple tuple = {};

	tuple.saddr = BACKEND_IP;
	tuple.daddr = CLIENT_IP;
	tuple.sport = bpf_htons(CLIENT_PORT);
	tuple.dport = bpf_htons(BACKEND_PORT);
	tuple.nexthdr = IPPROTO_TCP;
	tuple.flags = TUPLE_F_IN;

	struct ct_entry *entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!entry)
		test_fatal("could not find contract entry for packet.");

	if (entry->rev_nat_index != SOURCE_PERIMETER_NODE_REV_NAT_ID)
		test_error("incorrect rev_nat_id: got '%d' but expected '%d'",
			   entry->rev_nat_index, SOURCE_PERIMETER_NODE_REV_NAT_ID);

	test_finish();
}
