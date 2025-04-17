#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/*
 *
 * Test Situation
 *
 * This test covers a section of the resverse flow of the GDC-AG Perimeter/ELB when
 * a reply packet from a remote backend reaches the bare-metal node hosting the
 * perimeter node for the given flow.
 *
 * The packet arrives encapped with the geneve perimeter option holding the IP of
 * the destination backend pod (perimeter node).
 *
 * The program under test is bpf_host's from_netdev
 *
 * SOURCE: backend pod running on a remote bare metal node
 * DEST: perimeter node running on the local bare metal node
 *
 */

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

/* TEST VALUES */
#define SRC_NODE_MAC   mac_one
#define DST_NODE_MAC   mac_two

#define SRC_INFRA_NODE v4_node_one
#define DST_INFRA_NODE v4_node_two

/* Needed to determine if the packet should be decapped */
#define IPV4_DIRECT_ROUTING DST_INFRA_NODE

#define GENEVE_SRC_PORT 6081

/* Needed to determine if the packet should be decapped; 8472 is the value of
 * TUNNEL_PORT
 */
#define GENEVE_DST_PORT 8472

#define BACKEND_POD_IP		 v4_pod_one
#define EXT_CLIENT_IP		 v4_ext_one

#define BACKEND_PORT		 5000
#define EXT_CLIENT_PORT		 8000

#define DST_PERIMETER_NODE_IP	 v4_pod_two
#define PERIMETER_NODE_LXC_INDEX 12
#define PERIMETER_NODE_LXC_ID	 213

#define REV_NAT_ID		 33

/* TEST SET UP */
long mock_fib_lookup(__maybe_unused void *ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen,
		     __maybe_unused __u32 flags)
{
	params->ifindex = 0;

	return 0;
}

#undef ctx_redirect
#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused
int mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		      int ifindex __maybe_unused,
		      __u32 flags __maybe_unused)
{
	return CTX_ACT_REDIRECT;
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
		[PERIMETER_NODE_LXC_ID] = &mock_handle_policy,
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

#include "bpf_host.c"

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

#include "lib/google/pktgen.h"

PKTGEN("tc", "goog_gdc_perimeter_elb_host_reverse")
int goog_gdc_perimeter_elb_host_reverse_pktgen(struct __ctx_buff *ctx __maybe_unused)
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

		.direction = GENEVE_EGRESS_CLUSTER, /* Response ELB packet heading out of the cluster */

		.perimeter_node = DST_PERIMETER_NODE_IP,
	};

	int ret = google_pktgen__push_genevehdr(&builder, geneve_params);

	if (ret != TEST_PASS)
		return ret;

	/* IPv4 Header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->protocol = IPPROTO_TCP;
	l3->saddr = BACKEND_POD_IP;
	l3->daddr = EXT_CLIENT_IP;

	pktgen__finish(&builder);

	/* TCP Header */
	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = bpf_htons(BACKEND_PORT);
	l4->dest = bpf_htons(EXT_CLIENT_PORT);

	/* Packet Data */
	void *data =
		pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	return TEST_PASS;
}

SETUP("tc", "goog_gdc_perimeter_elb_host_reverse")
int goog_gdc_perimeter_elb_host_reverse_setup(struct __ctx_buff *ctx)
{
	/*
	 * Set Up Entry in Connection Map
	 *
	 * There will be an entry but it shouldn't be used for this
	 * section of the ELB flow.
	 */
	struct ipv4_ct_tuple tuple = {};
	struct ct_state ct_state = {};

	tuple.nexthdr = IPPROTO_TCP;
	tuple.saddr = BACKEND_POD_IP;
	tuple.daddr = EXT_CLIENT_IP;
	tuple.sport = bpf_htons(EXT_CLIENT_PORT);
	tuple.dport = bpf_htons(BACKEND_PORT);
	tuple.flags = TUPLE_F_IN;

	ct_state.rev_nat_index = REV_NAT_ID;
	ct_state.dsr_internal = 1;

	int result = ct_create4(get_ct_map4(&tuple),
				&CT_MAP_ANY4,
				&tuple,
				ctx,
				CT_EGRESS,
				&ct_state,
				NULL);

	if (result != 0)
		return TEST_ERROR;

	/* Set Up Perimeter Node */

	/* IP Cache */
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = DST_PERIMETER_NODE_IP,
	};

	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = DST_INFRA_NODE,
		.flag_skip_tunnel = true,
	};

	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* Endpoint Map */
	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = DST_PERIMETER_NODE_IP,
	};

	struct endpoint_info ep_value = {
		.ifindex = PERIMETER_NODE_LXC_INDEX,
		.lxc_id = PERIMETER_NODE_LXC_ID,
	};

	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	/* No Redirect Map Entries for this Section of the Flow */

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	return TEST_ERROR;
}

CHECK("tc", "goog_gdc_perimeter_elb_host_reverse")
int goog_gdc_perimeter_elb_host_reverse_check(struct __ctx_buff *ctx __maybe_unused)
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

	assert_ip_equal(EXT_CLIENT_IP, l3->daddr);
	assert_ip_equal(BACKEND_POD_IP, l3->saddr);

	/* Confirm Packet Is delivered to the Right LXC Interface */
	unsigned int dest_lxc_index = ctx_load_meta(ctx, CB_IFINDEX);

	if (dest_lxc_index != PERIMETER_NODE_LXC_INDEX)
		test_error("Expected lxc index '%d' got '%d'",
			   PERIMETER_NODE_LXC_INDEX, dest_lxc_index);

	test_finish();
}
