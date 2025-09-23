/*
 * The same values as used in google_gdc_perimeter_infra_host_forward.c
 *
 * The external client continues to be the original source in this
 * case. Dest continues to be the backend pod where the reverse flow
 * traffic originates.
 */
#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* FLAGS UNDER TEST */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_GOOGLE_GENEVE
#define ENCAP_IFINDEX 4
#define ENABLE_GOOGLE_VPC
#define ENABLE_HOST_FIREWALL
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_EGRESS_GATEWAY_COMMON

/* TURNS ON PERIMETER ELB */
#define ENABLE_EGRESS_GATEWAY_REDIRECT

/* TEST SCENARIO PACKET INFO */
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

/* Needed to determine if the packet should be decapped; value of TUNNEL_PORT */
#define GENEVE_DST_PORT 8472

#define CLIENT_IP     v4_ext_one
#define BACKEND_IP    v4_pod_one

#define CLIENT_PORT   4444
#define BACKEND_PORT  80

#define DEST_IF_INDEX 10
#define DEST_IF_ID    200

#define LXC_IPV4      212

/* Mocks */
#define fib_lookup    mock_fib_lookup

long mock_fib_lookup(__maybe_unused void *ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen,
		     __maybe_unused __u32 flags)
{
	params->ifindex = 0;

	return 0;
}

#define SECCTX_FROM_IPCACHE 1

__section("mock-handle-policy")
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_REDIRECT;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[LXC_IPV4] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic

static __always_inline __maybe_unused
void mock_tail_call_dynamic(struct __ctx_buff *ctx,
			    const void *map __maybe_unused,
			    __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

/* SET UP */
#include "bpf_lxc.c"

#include "node_config.h"
#include "lib/common.h"

#define FROM_CONTAINER 0

/* CRITICAL THIS COMES AFTER bpf_lxc.c */
#include "lib/google_perimeter_elb.h"

#include "lib/google/pktgen.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
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

PKTGEN("tc", "elb_infra_traffic_reverse_direction")
int elb_infra_traffic_reverse_direction_pktgen(struct __ctx_buff *ctx __maybe_unused)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	struct ethhdr *l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)SRC_NODE_MAC, (__u8 *)DST_NODE_MAC);

	/* IP Header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->protocol = (__u8)IPPROTO_TCP;
	l3->saddr = BACKEND_IP;
	l3->daddr = CLIENT_IP;

	/* TCP Header */
	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = bpf_htons(BACKEND_PORT);
	l4->dest = bpf_htons(CLIENT_PORT);

	/* Packet Data */
	void *data = pktgen__push_data(&builder,
				       default_data,
				       sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	struct ct_state ct_state = {};

	ct_state.rev_nat_index = SOURCE_PERIMETER_NODE_REV_NAT_ID;
	ct_state.dsr_internal = 1;
	ct_state.node_port = 0;

	int result = google_pktgen__create_existing_conn_tcp(ctx,
							     BACKEND_IP,
							     CLIENT_IP,
							     bpf_htons(BACKEND_PORT),
							     bpf_htons(CLIENT_PORT),
							     ct_state);

	if (result != TEST_PASS)
		return result;

	return TEST_PASS;
}

SETUP("tc", "elb_infra_traffic_reverse_direction")
int elb_infra_traffic_reverse_direction_setup(struct __ctx_buff *ctx __maybe_unused)
{
	add_allow_all_egress_policy();

	/* Set Up Backend Pod */
	struct ipcache_key backend_pod_cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};

	struct remote_endpoint_info backend_pod_cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = DST_INFRA_NODE,
		.flag_skip_tunnel = true,
	};

	map_update_elem(&IPCACHE_MAP, &backend_pod_cache_key,
			&backend_pod_cache_value, BPF_ANY);

	struct endpoint_key backend_pod_ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};

	struct endpoint_info backend_pod_ep_value = {
		.ifindex = DEST_IF_INDEX,
		.lxc_id = DEST_IF_ID,
	};

	map_update_elem(&ENDPOINTS_MAP, &backend_pod_ep_key,
			&backend_pod_ep_value, BPF_ANY);

	/* Set Up Perimeter Node and Destination Infra-Node */
	struct ipcache_key perimeter_node_cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = SOURCE_PERIMETER_NODE,
	};

	struct remote_endpoint_info perimeter_node_cache_value = {
		.sec_identity = 445566,
		.tunnel_endpoint = SRC_INFRA_NODE,
		.flag_skip_tunnel = false,
	};

	map_update_elem(&IPCACHE_MAP, &perimeter_node_cache_key,
			&perimeter_node_cache_value, BPF_ANY);

	/* Set Up Perimeter Node Maps */
	struct ipv4_redirect_ep redirect_ep_key = {
		.ip4 = SOURCE_PERIMETER_NODE,
	};

	__u16 redirect_ep_value = SOURCE_PERIMETER_NODE_REV_NAT_ID;

	map_update_elem(&GOOGLE_REDIRECT_EP_ID_V4_MAP, &redirect_ep_key,
			&redirect_ep_value, BPF_ANY);
	map_update_elem(&GOOGLE_REDIRECT_EP_IP_V4_MAP, &redirect_ep_value,
			&redirect_ep_key, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	return TEST_ERROR;
}

CHECK("tc", "elb_infra_traffic_reverse_direction")
int elb_infra_traffic_reverse_direction_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Check Full Packet Received */
	__u32 *status_code = data;

	if (*status_code != CTX_ACT_REDIRECT) {
		test_error("expected CTX_ACT_REDIRECT ('%d') but got '%d' instead",
			   CTX_ACT_REDIRECT, *status_code);
	}

	struct ethhdr *outer_l2 = data + sizeof(__u32);

	if ((void *)outer_l2 + sizeof(*outer_l2) > data_end)
		test_fatal("outer l2 out of bounds");

	struct iphdr *outer_l3 = (void *)outer_l2 + sizeof(*outer_l2);

	if ((void *)outer_l3 + sizeof(*outer_l3) > data_end)
		test_fatal("outer l3 out of bounds");

	struct udphdr *udp = (void *)outer_l3 + sizeof(*outer_l3);

	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("udp out of bounds");

	struct genevehdr *genevehdr = (void *)udp + sizeof(*udp);

	if ((void *)udp + sizeof(*genevehdr) > data_end)
		test_fatal("geneve out of bounds");

	struct geneve_perimeter_opt4 *gopt =
		(void *)genevehdr + sizeof(*genevehdr);

	if ((void *)gopt + sizeof(*gopt) > data_end)
		test_fatal("geneve option out of bounds");

	if ((void *)gopt + genevehdr->opt_len * 4 > data_end)
		test_fatal("geneve option length out of bounds")

	struct iphdr *inner_l3 = (void *)gopt + genevehdr->opt_len * 4;

	if ((void *)inner_l3 + sizeof(*inner_l3) > data_end)
		test_fatal("inner l3 out of bounds");

	if (inner_l3->protocol != IPPROTO_TCP) {
		test_fatal("inner l3 has unexpected protocol, expected '%d' but got '%d'",
			   IPPROTO_TCP, inner_l3->protocol);
	}

	struct tcphdr *inner_l4 = (void *)inner_l3 + sizeof(*inner_l4);

	if ((void *)inner_l4 + sizeof(*inner_l4) > data_end)
		test_fatal("inner l4 out bounds");

	/* Check Packet Values */

	/* Outer L3 */
	assert_ip_equal(SRC_INFRA_NODE, outer_l3->daddr);
	assert_ip_equal(DST_INFRA_NODE, outer_l3->saddr);

	/* Outer L4 */

	/*
	 * Source port is picked based on the hash of the outer (saddr, daddr,
	 * protocol, sport, dport)
	 *
	 * A floor value is used to ensure port picked is outside of privileged port range
	 */
	const __u32 MIN_GENEVE_SRC_PORT = (0 | 0x8000);

	if (bpf_ntohs(udp->source) < MIN_GENEVE_SRC_PORT) {
		test_error("unexpected source port on outer l4, got '%u' expected > '%u'",
			   bpf_ntohs(udp->source), MIN_GENEVE_SRC_PORT);
	}

	if (bpf_ntohs(udp->dest) != TUNNEL_PORT) {
		test_error("unexpected dest port on outer l4, expected '%u' but got '%u'",
			   TUNNEL_PORT, bpf_ntohs(udp->dest));
	}

	/* Geneve Header */
	if (genevehdr->opt_len * 4 != sizeof(*gopt))
		test_error("geneve has unexpected opt length");

	if (gopt->hdr.opt_class != bpf_htons(GOOGLE_GENEVE_OPT_CLASS))
		test_error("geneve opt has unexpected class ('%d')",
			   gopt->hdr.opt_class);

	if (gopt->hdr.type != PERIMETER_GENEVE_EGRESS_OPT_TYPE)
		test_error("geneve opt has unexpected type");

	if (gopt->hdr.length != PERIMETER_IPV4_GENEVE_OPT_LEN)
		test_error("geneve opt has unexpected length");

	test_log("checking geneve option perimeter node IP");
	assert_ip_equal(SOURCE_PERIMETER_NODE, gopt->addr);

	/* Inner L3 */
	assert_ip_equal(BACKEND_IP, inner_l3->saddr);
	assert_ip_equal(CLIENT_IP, inner_l3->daddr);

	/* Inner L4 */
	if (bpf_ntohs(inner_l4->source) != BACKEND_PORT) {
		test_error("unexpected source port on inner l4, expected '%u' but got '%u'",
			   BACKEND_PORT, bpf_ntohs(inner_l4->source));
	}

	if (bpf_ntohs(inner_l4->dest) != CLIENT_PORT)
		test_error("unexpected dest port on inner l4, expected '%u' but got '%u'",
			   CLIENT_PORT, bpf_ntohs(inner_l4->dest));

	test_finish();
}
