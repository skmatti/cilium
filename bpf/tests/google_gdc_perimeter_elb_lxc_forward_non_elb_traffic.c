/*
 * Test for non-elb traffic originating from the perimeter cluster
 *
 * The packet should get encapped but the geneve options should not be set if
 * the traffic originates from within the perimeter cluster.
 *
 * We are expecting the main ELB logic / redirection to be skipped and the
 * vanilla geneve and redirect to be used.
 *
* In the below diagram, the test point is "Test Point #1 - bpf_lxc"
 *
 * Link to diagram: https://screenshot.googleplex.com/tRXhX6pLx7fvPZh
 *
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
#define TUNNEL_MODE
#define MULTI_NIC_DEVICE_TYPE EP_DEV_TYPE_INDEX_MULTI_NIC_VETH /* Needed for perimeter network */

/* Enable ELB Features */
#define ENABLE_EGRESS_GATEWAY_REDIRECT
#define PERIMETER_ENDPOINT /* we are specifically testing the perimeter endpoint lxc program here */

/* TEST VALUES */

/* Src Infra-Cluster Node */
#define SRC_NODE_MAC mac_one
#define SRC_NODE_IP v4_node_one
#define SRC_NODE_IDENTITY HOST_ID
#define SRC_NODE_IFINDEX 0
#define SRC_NODE_IFID 0

#define IPV4_DIRECT_ROUTING SRC_NODE_IP

/* Src Perimeter Node LXC */
#define PERIMETER_NODE_LXC_MAC mac_two
#define PERIMETER_NODE_LXC_IP v4_pod_three
#define PERIMETER_NODE_LXC_IDENTITY 1002
#define PERIMETER_NODE_LXC_IFINDEX 12
#define PERIMETER_NODE_LXC_IFID 677

/* Src Perimeter Node */
#define PERIMETER_NODE_MAC mac_three
#define PERIMETER_NODE_IP v4_pod_one
#define PERIMETER_NODE_IDENTITY 1003
#define PERIMETER_NODE_IFINDEX 14
#define PERIMETER_NODE_IFID 872

/* Src Pod Info */
#define SRC_POD_IP IPV4(192, 168, 0, 4) /* ran out of premade IPs */
#define SRC_POD_IDENTITY 1004

#define SRC_PORT 5000


/* Dst Infra-Cluster Node */
#define DST_NODE_MAC mac_four
#define DST_NODE_IP v4_node_one
#define DST_NODE_IDENTITY 2001

/* Destination VM node */
#define DST_VM_NODE_MAC mac_five
#define DST_VM_NODE_IP IPV4(192, 168, 0, 5)
#define DST_VM_NODE_LXC_IP IPV4(192, 168, 0, 6)
#define DST_VM_NODE_IDENTITY 2002

/* Destination Pod Info */
#define DST_POD_IP IPV4(192, 168, 0, 7)
#define DST_POD_IDENTITY 2003

#define DST_PORT 8080


#define fib_lookup mock_fib_lookup

long mock_fib_lookup(__maybe_unused void *ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen,
		     __maybe_unused __u32 flags)
{
	__bpf_memcpy_builtin(params->smac, (__u8 *)SRC_NODE_MAC, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)DST_NODE_MAC, ETH_ALEN);

	return BPF_FIB_LKUP_RET_SUCCESS;
}

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

PKTGEN("tc", "google_gdc_perimeter_elb_lxc_forward_non_elb_traffic")
int google_gdc_perimeter_elb_lxc_forward_non_elb_traffic_pktgen(struct __ctx_buff* ctx __maybe_unused)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	struct ethhdr *l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *) PERIMETER_NODE_MAC /* src mac */, (__u8*) SRC_NODE_MAC /* destination mac */);

	/* IPv4 Header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->protocol = (__u8) IPPROTO_TCP;
	l3->saddr = SRC_POD_IP;
	l3->daddr = DST_POD_IP;

	/* TCP Header */
	struct tcphdr* l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = bpf_htons(SRC_PORT);
	l4->dest = bpf_htons(DST_PORT);

	/* Packet Data */
	void *data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "google_gdc_perimeter_elb_lxc_forward_non_elb_traffic")
int google_gdc_perimeter_elb_lxc_forward_non_elb_traffic_setup(struct __ctx_buff* ctx __maybe_unused)
{
	add_allow_all_egress_policy();

	/* src node set up */
	ipcache_v4_add_entry(SRC_NODE_IP, 0, SRC_NODE_IDENTITY, 0, 0);

	endpoint_v4_add_entry(SRC_NODE_IP, SRC_NODE_IFINDEX, SRC_NODE_IFID, ENDPOINT_F_HOST,
			      SRC_NODE_IDENTITY, (__u8*) SRC_NODE_MAC, (__u8*) SRC_NODE_MAC);

	/* perimeter virt-launcher pod set up */
	ipcache_v4_add_entry(PERIMETER_NODE_LXC_IP, 0, PERIMETER_NODE_LXC_IDENTITY, 0, 0);

	endpoint_v4_add_entry(PERIMETER_NODE_LXC_IP, PERIMETER_NODE_IFINDEX, SRC_NODE_IFID, ENDPOINT_F_MULTI_NIC_VETH,
			      PERIMETER_NODE_LXC_IDENTITY, (__u8*) PERIMETER_NODE_LXC_MAC, (__u8*) SRC_NODE_MAC);

	/* src pod set up */
	ipcache_v4_add_entry(SRC_POD_IP, 0, SRC_POD_IDENTITY, PERIMETER_NODE_IP, 0);

	/* dst node set up */
	ipcache_v4_add_entry(DST_NODE_IP, 0, DST_NODE_IDENTITY, 0, 0);

	/* destination vm set up */
	ipcache_v4_add_entry(DST_VM_NODE_IP, 0, DST_VM_NODE_IDENTITY, DST_NODE_IP, 0);

	/* destination pod */
	ipcache_v4_add_entry(DST_POD_IP, 0, DST_POD_IDENTITY, DST_VM_NODE_IP, 0);

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	return TEST_ERROR;
}

CHECK("tc", "google_gdc_perimeter_elb_lxc_forward_non_elb_traffic")
int google_gdc_perimeter_elb_lxc_forward_non_elb_traffic_check(struct __ctx_buff* ctx __maybe_unused)
{
	void* data, *data_end;
	__u32* status_code;

	struct ethhdr* l2;
	struct iphdr* outer_l3, *inner_l3;
	struct udphdr* udp;
	struct tcphdr* inner_l4;
	struct genevehdr* geneve;
	struct geneve_perimeter_opt4 *gopt;

	test_init();

	data = (void *)(long) ctx_data(ctx);
	data_end = (void *)(long) ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("expected CTX_ACT_REDIRECT ('%d') but got '%d'", CTX_ACT_REDIRECT, *status_code);

	/* Parse packet data */

	l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("outer l2 out of bounds");

	outer_l3 = (void *)l2 + sizeof(*l2);

	if ((void *)outer_l3 + sizeof(*outer_l3) > data_end)
		test_fatal("outer l3 out of bounds");

	udp = (void *)outer_l3 + sizeof(*outer_l3);
	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("udp out of bounds");

	geneve = (void *)udp + sizeof(*udp);
	if ((void *)geneve + sizeof(*geneve) > data_end)
		test_fatal("geneve out of bounds");

	gopt = (void *)geneve + sizeof(*geneve);

	if ((void *)gopt + sizeof(*gopt) > data_end)
		test_fatal("gopt out of bounds");

	if ((void *)gopt + geneve->opt_len * 4 > data_end)
		test_fatal("geneve opts out of bounds");

	inner_l3 = (void *)gopt + geneve->opt_len * 4;

	if ((void *)inner_l3 + sizeof(*inner_l3) > data_end)
		test_fatal("inner l3 out of bounds");

	inner_l4 = (void *)inner_l3 + sizeof(*inner_l3);

	if ((void *)inner_l4 + sizeof(*inner_l4) > data_end)
		test_fatal("tcp out of bounds");

	/* TODO: lconnery (b/450614670) geneve option should not be set for
	 * non-ELB traffic
	 */
	/* Inspect geneve options */
	if (geneve->opt_len == 0)
		test_error("geneve opt len expected '1' but got '%d'", geneve->opt_len);

	/* Check outer IPs */
	assert_ip_equal(SRC_NODE_IP, outer_l3->saddr);
	assert_ip_equal(DST_NODE_IP, outer_l3->daddr);

	/* Check inner IPs */
	assert_ip_equal(SRC_POD_IP, inner_l3->saddr);
	assert_ip_equal(DST_POD_IP, inner_l3->daddr);

	assert_num_equal(SRC_PORT, bpf_htons(inner_l4->source));
	assert_num_equal(DST_PORT, bpf_htons(inner_l4->dest));

	test_finish();
}
