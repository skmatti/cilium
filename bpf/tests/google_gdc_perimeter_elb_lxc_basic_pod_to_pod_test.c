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
#define TUNNEL_MODE

/* TURNS ON PERIMETER ELB  */
#define ENABLE_EGRESS_GATEWAY_REDIRECT

/* TEST VALUES */
#define SRC_NODE_IP v4_node_one
#define DST_NODE_IP v4_node_two

/* Needed to determine if the packet should be decapped */
#define IPV4_DIRECT_ROUTING SRC_NODE_IP

#define SRC_POD_IP v4_pod_one
#define DST_POD_IP v4_pod_two

#define SRC_PORT 5000
#define DST_PORT 4040

#define LXC_INDEX 10

#define SRC_POD_LXC

#include "bpf_lxc.c"

#include "lib/google/pktgen.h"
#include "lib/ipcache.h"

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

PKTGEN("tc", "google_gdc_perimeter_elb_lxc_basic_pod_to_pod_test")
int google_gdc_perimeter_elb_lxc_basic_pod_to_pod_test_pktgen(struct __ctx_buff *ctx __maybe_unused)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	struct ethhdr *l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	/* IPv4 Header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->protocol = (__u8)IPPROTO_TCP;
	l3->saddr = SRC_POD_IP;
	l3->daddr = DST_POD_IP;

	/* TCP Header */
	struct tcphdr* l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = bpf_htons(SRC_PORT);
	l4->dest = bpf_htons(DST_PORT);

	/* Packet Data */
	void* data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "google_gdc_perimeter_elb_lxc_basic_pod_to_pod_test")
int google_gdc_perimeter_elb_lxc_basic_pod_to_pod_test_setup(struct __ctx_buff* ctx __maybe_unused)
{
	add_allow_all_egress_policy();

	/* Add nodes to IP Cache */
	ipcache_v4_add_entry(bpf_htonl(SRC_NODE_IP), 0, HOST_ID, 0, 0);

	ipcache_v4_add_entry(bpf_htonl(DST_NODE_IP), 0, HOST_ID, 0, 0);

	/* Set up src pod maps */
	struct ipcache_key src_pod_cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = SRC_POD_IP,
	};

	struct remote_endpoint_info src_pod_cache_value = {
		.sec_identity = 111222333,
		.tunnel_endpoint = bpf_htonl(SRC_NODE_IP),
	};

	map_update_elem(&IPCACHE_MAP, &src_pod_cache_key, &src_pod_cache_value, BPF_ANY);

	struct endpoint_key src_pod_ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = SRC_POD_IP,
	};

	struct endpoint_info src_pod_ep_value = {
		.ifindex = LXC_INDEX,
		.lxc_id = LXC_ID,
	};

	map_update_elem(&ENDPOINTS_MAP, &src_pod_ep_key, &src_pod_ep_value, BPF_ANY);

	/* Set up dst pod maps */
	struct ipcache_key dst_pod_cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = DST_POD_IP,
	};

	struct remote_endpoint_info dst_pod_cache_value = {
		.sec_identity = 444555666,
		.tunnel_endpoint = bpf_htonl(DST_NODE_IP),
	};

	map_update_elem(&IPCACHE_MAP, &dst_pod_cache_key, &dst_pod_cache_value, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	return TEST_ERROR;
}

CHECK("tc", "google_gdc_perimeter_elb_lxc_basic_pod_to_pod_test")
int google_gdc_perimeter_elb_lxc_basic_pod_to_pod_test_check(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	void *data = (void*)(long) ctx_data(ctx);
	void *data_end = (void *)(long) ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	/* Check Full Packet Received */
	__u32 *status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_error("expected CTX_ACT_REDIRECT ('%d') but got '%d' instead", CTX_ACT_REDIRECT, *status_code);

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

	struct geneve_perimeter_opt4 *gopt = (void *)genevehdr + sizeof(*genevehdr);

	if ((void *)gopt + sizeof(*gopt) > data_end)
		test_fatal("geneve option out of bounds");

	if ((void *)gopt + genevehdr->opt_len * 4 > data_end)
		test_fatal("geneve option length out of bounds")

	struct iphdr *inner_l3 = (void *)gopt + genevehdr->opt_len * 4;

	if ((void *)inner_l3 + sizeof(*inner_l3) > data_end)
		test_fatal("inner l3 out of bounds");

	if (inner_l3->protocol != IPPROTO_TCP) {
		test_error("inner l3, expected protocol '%d' but got '%d'", IPPROTO_TCP, inner_l3->protocol);
	}

	struct tcphdr *inner_l4 = (void *)inner_l3 + sizeof(*inner_l4);

	if ((void *)inner_l4 + sizeof(*inner_l4) > data_end)
		test_fatal("inner l4 out bounds");

	/* Check Packet Values */

	/* Outer L3 */
	assert_ip_equal(SRC_NODE_IP, IPV4_DIRECT_ROUTING);
	assert_ip_equal(DST_NODE_IP, bpf_ntohl(outer_l3->daddr));

	/* Inner L4 */
	if (bpf_ntohs(inner_l4->source) != SRC_PORT) {
		test_error("unexpected source port on inner l4, expected '%u' but got '%u'",
			   SRC_PORT, bpf_ntohs(inner_l4->source));
	}

	if (bpf_ntohs(inner_l4->dest) != DST_PORT)
		test_error("unexpected dest port on inner l4, expected '%u' but got '%u'",
			   DST_PORT, bpf_ntohs(inner_l4->dest));

	/* Check perimeter redirect geneve options are not set */
	if (gopt->addr != 0)
		test_error("expected empty perimeter geneve option but address is '%d'", gopt->addr);

	test_finish();
}