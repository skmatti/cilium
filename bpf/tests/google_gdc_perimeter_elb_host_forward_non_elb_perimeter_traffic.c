/*
 * Test for Non-ELB Traffic that has originiated in the perimeter Cluster
 *
 * The packet will arrived encapped with the perimeter option set due to
 * b/450614670. In this flow, despite the perimeter option being set on the
 * geneve header, we expect the ELB hook path to be returned from early.
 *
 * In the below diagram, the test point is "Test Point #2 - bpf_host"
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
#define ENABLE_GOOGLE_MULTI_NIC
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_EGRESS_GATEWAY_COMMON
#define ENABLE_DSR		1
#define DSR_ENCAP_GENEVE	3
#define ENABLE_HOST_ROUTING

/* TURNS ON PERIMETER ELB */
#define ENABLE_EGRESS_GATEWAY_REDIRECT

/* Skip ingress policy checks */
#define USE_BPF_PROG_FOR_INGRESS_POLICY

/* TEST VALUES */

/* Src Infra-Cluster Node */
#define SRC_NODE_MAC mac_one
#define SRC_NODE_IP v4_node_one
#define SRC_NODE_IDENTITY 3232
#define SRC_NODE_IFINDEX 2
#define SRC_NODE_IFID 212

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


/* GENEVE PORTS */
#define GENEVE_SRC_PORT 6081
#define GENEVE_DST_PORT 8472


/* Dst Infra-Cluster Node */
#define DST_NODE_MAC mac_four
#define DST_NODE_IP v4_node_one
#define DST_NODE_IDENTITY HOST_ID
#define DST_NODE_IFINDEX 0
#define DST_NODE_IFID 0

#define IPV4_DIRECT_ROUTING DST_NODE_IP

/* Destination VM node */
#define DST_VM_NODE_MAC mac_five
#define DST_VM_NODE_IP IPV4(192, 168, 0, 5)
#define DST_VM_NODE_LXC_IP IPV4(192, 168, 0, 6)
#define DST_VM_NODE_IDENTITY 2002
#define DST_VM_NODE_IFINDEX 84
#define DST_VM_NODE_IFID 899

/* Destination Pod Info */
#define DST_POD_IP IPV4(192, 168, 0, 7)
#define DST_POD_IDENTITY 2003

#define DST_PORT 8080

/* END TEST VALUES */

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(__maybe_unused void *ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen,
		     __maybe_unused __u32 flags)
{
	__bpf_memcpy_builtin(params->smac, (__u8 *)DST_NODE_MAC, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)DST_VM_NODE_MAC, ETH_ALEN);

	return BPF_FIB_LKUP_RET_SUCCESS;
}

#include "bpf_host.c"

#include "lib/google/pktgen.h"
#include "lib/ipcache.h"
#include "lib/endpoint.h"
#include "lib/google/pktgen.h"

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

#undef ctx_redirect
#define ctx_redirect mock_ctx_redirect

static __always_inline __maybe_unused int mock_ctx_redirect(struct __sk_buff *ctx,
							    int ifindex __maybe_unused,
							    __u32 flags __maybe_unused)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct iphdr *ip4;

	ip4 = data + sizeof(struct ethhdr);
	if ((void *)ip4 + sizeof(*ip4) > data_end)
		return CTX_ACT_DROP;

	/* Forward to backend: */
	if (ip4->saddr == SRC_POD_IP && ifindex == DST_VM_NODE_IFINDEX) {
		ctx_store_meta(ctx, CB_IFINDEX, ifindex);
		return CTX_ACT_REDIRECT;
	}

	return CTX_ACT_DROP;
}

PKTGEN("tc", "google_gdc_perimeter_elb_host_forward_non_elb_perimeter_traffic")
int google_gdc_perimeter_elb_host_forward_non_elb_perimeter_traffic_pktgen(struct __ctx_buff* ctx __maybe_unused)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	struct google_pktgen__genevehdr_params geneve_params = {
		.src_mac = (__u8 *)SRC_NODE_MAC,
		.dst_mac = (__u8 *)DST_NODE_MAC,

		.outer_src_ip = SRC_NODE_IP,
		.outer_dst_ip = DST_NODE_IP,

		.outer_src_port = GENEVE_SRC_PORT,
		.outer_dst_port = GENEVE_DST_PORT,

		.direction = GENEVE_INGRESS_CLUSTER,

		.perimeter_node = PERIMETER_NODE_IP,
	};

	int ret = google_pktgen__push_genevehdr(&builder, geneve_params);

	if (ret != TEST_PASS)
		return ret;

	/* IPv4 Header */
	struct iphdr* l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->saddr = SRC_POD_IP;
	l3->daddr = DST_POD_IP;
	l3->protocol = IPPROTO_TCP;

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

	google_pktgen__finish_geneve_pkt(&builder);

	return TEST_PASS;
}

SETUP("tc", "google_gdc_perimeter_elb_host_forward_non_elb_perimeter_traffic")
int google_gdc_perimeter_elb_host_forward_non_elb_perimeter_traffic_setup(struct __ctx_buff* ctx __maybe_unused)
{
	/* src node set up */
	ipcache_v4_add_entry(SRC_NODE_IP, 0, SRC_NODE_IDENTITY, 0, 0);

	/* perimeter virt-launcher pod set up */
	ipcache_v4_add_entry(PERIMETER_NODE_LXC_IP, 0, PERIMETER_NODE_LXC_IDENTITY, 0, 0);

	/* src pod set up */
	ipcache_v4_add_entry(SRC_POD_IP, 0, SRC_POD_IDENTITY, PERIMETER_NODE_IP, 0);

	/* dst node set up */
	ipcache_v4_add_entry(DST_NODE_IP, 0, DST_NODE_IDENTITY, 0, 0);

	endpoint_v4_add_entry(DST_NODE_IP, DST_NODE_IFINDEX, DST_NODE_IFID, ENDPOINT_F_HOST,
			      DST_NODE_IDENTITY, (__u8*) DST_NODE_MAC, (__u8*) DST_NODE_MAC);

	/* destination vm set up */
	ipcache_v4_add_entry(DST_VM_NODE_IP, 0, DST_VM_NODE_IDENTITY, DST_NODE_IP, 0);

	endpoint_v4_add_entry(DST_VM_NODE_IP, DST_NODE_IFINDEX, DST_NODE_IFID, ENDPOINT_F_MULTI_NIC_VETH,
			      DST_VM_NODE_IDENTITY, (__u8*) DST_VM_NODE_MAC, (__u8*) DST_NODE_MAC);

	/* destination pod */
	ipcache_v4_add_entry(DST_POD_IP, 0, DST_POD_IDENTITY, DST_VM_NODE_IP, 0);

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	return TEST_ERROR;
}

CHECK("tc", "google_gdc_perimeter_elb_host_forward_non_elb_perimeter_traffic")
int google_gdc_perimeter_elb_host_forward_non_elb_perimeter_traffic_check(struct __ctx_buff* ctx __maybe_unused)
{
	void* data, *data_end;
	__u32* status_code;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;

	test_init();

	data = (void *)(long) ctx_data(ctx);
	data_end = (void *)(long) ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_error("expected CTX_ACT_REDIRECT ('%d') but got '%d'", CTX_ACT_REDIRECT, *status_code);

	l2 = data + sizeof(__u32);

	if ((void *) l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *) l2 + sizeof(struct ethhdr);

	if ((void *) l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *) l3 + sizeof(struct iphdr);

	if ((void *) l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* check header values */
	assert_ip_equal(SRC_POD_IP, l3->saddr);
	assert_ip_equal(DST_POD_IP, l3->daddr);

	assert_num_equal(SRC_PORT, bpf_htons(l4->source));
	assert_num_equal(DST_PORT, bpf_htons(l4->dest));

	/* Inspect redirect map and CT table to make sure ELB path is not taken */
	struct ipv4_redirect_ep redirect_ep_key = {.ip4 = PERIMETER_NODE_IP};

	__u16* redirect_ep_id = map_lookup_elem(&GOOGLE_REDIRECT_EP_ID_V4_MAP, &redirect_ep_key);

	if (redirect_ep_id) {
		test_error("no entry found for this packet in redirect map")
	}

	test_finish();
}
