#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/*
 *
 * Test Situation
 *
 * This test covers the reverse flow for GDC-AG's Perimeter ELB when the
 * backend pod is hosted on the same node as the perimeter node.
 *
 * It should pick up that the packet is a REPLY and an entry in the Perimeter
 * Redirect maps should be found.
 *
 * The packet should then be redirected to the Perimeter Node LXC interface.
 *
 * The program under test is bpf_lxc from_container.
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

/* TURNS ON PERIMETER ELB  */
#define ENABLE_EGRESS_GATEWAY_REDIRECT

/* TEST VALUES */
#define BARE_METAL_NODE_IP v4_node_one

/* Needed to determine if the packet should be decapped */
#define IPV4_DIRECT_ROUTING BARE_METAL_NODE_IP

#define BACKEND_MAC		 mac_one
#define EXT_CLIENT_MAC		 mac_two

#define BACKEND_POD_IP		 v4_pod_one
#define EXT_CLIENT_IP		 v4_ext_one

#define BACKEND_POD_PORT	 5000
#define EXT_CLIENT_PORT		 4040

#define DST_PERIMETER_NODE_IP	 v4_pod_two
#define PERIMETER_NODE_LXC_INDEX 34
#define PERIMETER_NODE_LXC_ID	 122

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

static __always_inline __maybe_unused void mock_tail_call_dynamic(struct __ctx_buff *ctx,
								  const void *map __maybe_unused,
								  __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#include "bpf_lxc.c"

#define FROM_CONTAINER 0

#include "lib/google/pktgen.h"

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

PKTGEN("tc", "google_elb_lxc_rev_local_perimeter_node")
int google_elb_lxc_rev_local_perimeter_node_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	struct ethhdr *l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)BACKEND_MAC, (__u8 *)EXT_CLIENT_MAC);

	/* IPv4 Header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->protocol = (__u8)IPPROTO_TCP;
	l3->saddr = BACKEND_POD_IP;
	l3->daddr = EXT_CLIENT_IP;

	/* TCP Header */
	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = bpf_htons(BACKEND_POD_PORT);
	l4->dest = bpf_htons(EXT_CLIENT_PORT);

	/* Packet Data */
	void *data =
		pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "google_elb_lxc_rev_local_perimeter_node")
int google_elb_lxc_rev_local_perimeter_node_setup(struct __ctx_buff *ctx)
{
	add_allow_all_egress_policy();

	/* Set Up Connection Map */
	struct ct_state ct_state = {
		.rev_nat_index = REV_NAT_ID,
		.dsr_internal = 1,
	};

	cilium_dbg(ctx, DBG_GENERIC, 444000, __LINE__);

	int result = google_pktgen__create_existing_conn_tcp(ctx,
							     BACKEND_POD_IP,
							     EXT_CLIENT_IP,
							     bpf_htons(BACKEND_POD_PORT),
							     bpf_htons(EXT_CLIENT_PORT),
							     ct_state);

	if (result != TEST_PASS)
		return result;

	/* Add Perimeter Node to IP Cache and Endpoints Map */

	/* IP Cache */
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = DST_PERIMETER_NODE_IP,
	};

	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = BARE_METAL_NODE_IP,
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

	/* Add Perimeter Redirect Entries */
	struct ipv4_redirect_ep redirect_ep_key = {
		.ip4 = DST_PERIMETER_NODE_IP,
	};

	/* Matches entry in the connection map */
	__u16 redirect_ep_value = REV_NAT_ID;

	map_update_elem(&GOOGLE_REDIRECT_EP_ID_V4_MAP, &redirect_ep_key,
			&redirect_ep_value, BPF_ANY);
	map_update_elem(&GOOGLE_REDIRECT_EP_IP_V4_MAP, &redirect_ep_value,
			&redirect_ep_key, BPF_ANY);

	cilium_dbg(ctx, DBG_GENERIC, 444000, __LINE__);

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	return TEST_ERROR;
}

CHECK("tc", "google_elb_lxc_rev_local_perimeter_node")
int google_elb_lxc_rev_local_perimeter_node_check(struct __ctx_buff *ctx)
{
	test_init();

	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	__u32 *status_code = data;

	if (*status_code != CTX_ACT_REDIRECT) {
		test_error("expected CTX_ACT_REDIRECT ('%d') but got '%d' instead",
			   CTX_ACT_REDIRECT, *status_code);
	}

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

	if (bpf_ntohs(l4->dest) != EXT_CLIENT_PORT) {
		test_error("unexpected dest port. expected '%d' but got '%d'",
			   EXT_CLIENT_PORT, bpf_ntohs(l4->dest));
	}

	if (bpf_ntohs(l4->source) != BACKEND_POD_PORT) {
		test_error("unexpected source port. expected '%d' but got '%d'",
			   BACKEND_POD_PORT, bpf_ntohs(l4->source));
	}

	/* Confirm Packet is Sent to Correct LXC Interface */
	unsigned int dest_lxc_index = ctx_load_meta(ctx, CB_IFINDEX);

	if (dest_lxc_index != PERIMETER_NODE_LXC_INDEX) {
		test_error("incorrect lxc index, expected '%u'but got '%u'",
			   PERIMETER_NODE_LXC_INDEX, dest_lxc_index);
	}

	test_finish();
}
