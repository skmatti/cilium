/* TEST VALUES */
#define SRC_NODE_MAC mac_one
#define DST_NODE_MAC mac_two

#define SRC_NODE_IP v4_node_one
#define DST_NODE_IP v4_node_two

#define SRC_POD_IP v4_pod_one
#define DST_POD_IP v4_pod_two

#define DST_REMOTE_VM_POD_IP 0x0A000202
#define DST_REMOTE_VM_IP 0x0A0000FD /* 10.0.0.253 */
#define DST_INFRA_NODE_IP 0x0A0000FC /* 10.0.0.252 */


#define SRC_PORT 5000
#define DST_PORT 4040

#define LXC_INDEX 10
#define TEST_LXC_ID 100

long mock_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags);
#define fib_lookup mock_fib_lookup

#include "bpf_lxc.c"
#include "lib/google/pktgen.h"

#include "lib/ipcache.h"

static __always_inline
int verify_ct_entry(__be32 saddr, __be32 daddr, __u8 proto, __be16 sport, __be16 dport)
{
	struct ipv4_ct_tuple tuple = {};
	tuple.saddr = saddr;
	tuple.daddr = daddr;
	tuple.nexthdr = proto;
	tuple.sport = sport;
	tuple.dport = dport;
	tuple.flags = TUPLE_F_IN; // Egress flow created as IN from pod

	void *map = get_ct_map4(&tuple);
	void *val = map_lookup_elem(map, &tuple);
	if (!val) {
		return 0;
	}
	return 1;
}

long mock_fib_lookup(__maybe_unused void *ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen,
		     __maybe_unused __u32 flags)
{
	__bpf_memcpy_builtin(params->smac, (__u8 *)SRC_NODE_MAC, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)DST_NODE_MAC, ETH_ALEN);

	return BPF_FIB_LKUP_RET_SUCCESS;
}

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

/*
 * Case 1: Pod to Remote Node
 */
PKTGEN("tc", "pod_to_remote_node")
int pod_to_remote_node_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	if (!pktgen__push_ethhdr(&builder)) return TEST_ERROR;
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);
	if (!l3) return TEST_ERROR;
	l3->saddr = SRC_POD_IP;
	l3->daddr = DST_NODE_IP; /* To Remote Node */

	struct tcphdr* l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4) return TEST_ERROR;
	l4->source = bpf_htons(SRC_PORT);
	l4->dest = bpf_htons(DST_PORT);

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data))) return TEST_ERROR;
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "pod_to_remote_node")
int pod_to_remote_node_setup(struct __ctx_buff *ctx)
{
	add_allow_all_egress_policy();
	/* Src Pod Setup */
	struct endpoint_key src_pod_ep_key = { .family = ENDPOINT_KEY_IPV4, .ip4 = SRC_POD_IP };
	struct endpoint_info src_pod_ep_value = { .ifindex = LXC_INDEX, .lxc_id = TEST_LXC_ID };
	map_update_elem(&ENDPOINTS_MAP, &src_pod_ep_key, &src_pod_ep_value, BPF_ANY);

	/* Dst: Remote Node */
	/* In IPCACHE, Node maps to HOST_ID and tunnel_endpoint = Node IP. */
	struct ipcache_key node_key = { .lpm_key = { .prefixlen = 32 }, .family = ENDPOINT_KEY_IPV4, .ip4 = DST_NODE_IP };
	struct remote_endpoint_info node_val = { .sec_identity = HOST_ID, .tunnel_endpoint = bpf_htonl(DST_NODE_IP) };
	map_update_elem(&IPCACHE_MAP, &node_key, &node_val, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "pod_to_remote_node")
int pod_to_remote_node_check(struct __ctx_buff *ctx)
{
	test_init();
	void *data = (void*)(long) ctx_data(ctx);
	void *data_end = (void *)(long) ctx->data_end;

	__u32 *status_code = data;
	if ((void*)(status_code + 1) > data_end) test_fatal("bounds");
#if GOOGLE_IPSEC_MODE == 1
	if (*status_code != CTX_ACT_OK)
		test_error("expected OK, got %d", *status_code);
#else
	if (*status_code != CTX_ACT_REDIRECT)
		test_error("expected redirect, got %d", *status_code);
#endif

	/* Parse Geneve/Outer */
	struct ethhdr *outer_l2 = (void *)(status_code + 1);
	if ((void *)(outer_l2 + 1) > data_end) test_fatal("outer l2 bounds");
	struct iphdr *outer_l3 = (void *)(outer_l2 + 1);
	if ((void *)(outer_l3 + 1) > data_end) test_fatal("outer l3 bounds");

	/* Expect Dst = DST_NODE_IP */
	assert_ip_equal(DST_NODE_IP, bpf_ntohl(outer_l3->daddr));
	assert_ip_equal(IPV4_DIRECT_ROUTING, outer_l3->saddr); /* SRC_NODE_IP */

	/* Verify Geneve and proper defaults */
	struct udphdr *udp = (void *)(outer_l3 + 1);
	if ((void *)(udp + 1) > data_end) test_fatal("udp bounds");

	/* Outer UDP Dst Port = TUNNEL_PORT (Geneve) */
	if (bpf_ntohs(udp->dest) != TUNNEL_PORT)
		test_error("expected outer udp dest port %d, got %d", TUNNEL_PORT, bpf_ntohs(udp->dest));

	struct genevehdr *gh = (void *)(udp + 1);
	if ((void *)(gh + 1) > data_end) test_fatal("geneve bounds");

	/* Inner Packet Validation */
	__u32 opt_bytes = gh->opt_len * 4;
	struct iphdr *inner_l3 = (void *)((char *)gh + sizeof(*gh) + opt_bytes);
	if ((void *)(inner_l3 + 1) > data_end) test_fatal("inner l3 bounds");

	assert_ip_equal(SRC_POD_IP, inner_l3->saddr);
	assert_ip_equal(DST_NODE_IP, inner_l3->daddr);

	if (inner_l3->protocol != IPPROTO_TCP)
		test_error("expected inner protocol TCP, got %d", inner_l3->protocol);

	struct tcphdr *inner_l4 = (void *)(inner_l3 + 1);
	if ((void *)(inner_l4 + 1) > data_end) test_fatal("inner l4 bounds");

	if (bpf_ntohs(inner_l4->source) != SRC_PORT)
		test_error("expected inner src port %d, got %d", SRC_PORT, bpf_ntohs(inner_l4->source));
	if (bpf_ntohs(inner_l4->dest) != DST_PORT)
		test_error("expected inner dst port %d, got %d", DST_PORT, bpf_ntohs(inner_l4->dest));

	test_finish();
}

/*
 * Case 2: Pod to Pod (Standard/BM)
 * One layer of tunnel lookup.
 */
PKTGEN("tc", "pod_to_pod")
int pod_to_pod_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);
	if (!pktgen__push_ethhdr(&builder)) return TEST_ERROR;
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);
	if (!l3) return TEST_ERROR;
	l3->saddr = SRC_POD_IP;
	l3->daddr = DST_POD_IP;
	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4) return TEST_ERROR;
	l4->source = bpf_htons(SRC_PORT);
	l4->dest = bpf_htons(DST_PORT);

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data))) return TEST_ERROR;
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "pod_to_pod")
int pod_to_pod_setup(struct __ctx_buff *ctx)
{
	add_allow_all_egress_policy();
	/* Src Pod Setup */
	struct endpoint_key src_pod_ep_key = { .family = ENDPOINT_KEY_IPV4, .ip4 = SRC_POD_IP };
	struct endpoint_info src_pod_ep_value = { .ifindex = LXC_INDEX, .lxc_id = TEST_LXC_ID };
	map_update_elem(&ENDPOINTS_MAP, &src_pod_ep_key, &src_pod_ep_value, BPF_ANY);

	/* Dst Pod -> Node IP */
	struct ipcache_key pod_key = { .lpm_key = { .prefixlen = 32 }, .family = ENDPOINT_KEY_IPV4, .ip4 = DST_POD_IP };
	struct remote_endpoint_info pod_val = { .sec_identity = 200, .tunnel_endpoint = bpf_htonl(DST_NODE_IP) };
	map_update_elem(&IPCACHE_MAP, &pod_key, &pod_val, BPF_ANY);

	/* Recursive check: Node IP -> Node Identity */
	struct ipcache_key node_key = { .lpm_key = { .prefixlen = 32 }, .family = ENDPOINT_KEY_IPV4, .ip4 = DST_NODE_IP };
	struct remote_endpoint_info node_val = { .sec_identity = HOST_ID, .tunnel_endpoint = bpf_htonl(DST_NODE_IP) };
	map_update_elem(&IPCACHE_MAP, &node_key, &node_val, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "pod_to_pod")
int pod_to_pod_check(struct __ctx_buff *ctx)
{
	test_init();
	void *data = (void*)(long) ctx_data(ctx);
	void *data_end = (void *)(long) ctx->data_end;

	__u32 *status_code = data;
	if ((void*)(status_code + 1) > data_end) test_fatal("bounds");
#if GOOGLE_IPSEC_MODE == 1
	if (*status_code != CTX_ACT_OK)
		test_error("expected OK, got %d", *status_code);
#else
	if (*status_code != CTX_ACT_REDIRECT)
		test_error("expected redirect, got %d", *status_code);
#endif

	struct ethhdr *outer_l2 = (void *)(status_code + 1);
	struct iphdr *outer_l3 = (void *)(outer_l2 + 1);
	if ((void *)(outer_l3 + 1) > data_end) test_fatal("outer l3 bounds");

	/* Expect Dst = DST_NODE_IP */
	assert_ip_equal(DST_NODE_IP, bpf_ntohl(outer_l3->daddr));
	assert_ip_equal(IPV4_DIRECT_ROUTING, outer_l3->saddr); /* SRC_NODE_IP */

	/* Validate inner packet */
	struct udphdr *udp = (void *)(outer_l3 + 1);
	if ((void *)(udp + 1) > data_end) test_fatal("udp bounds");

	/* Outer UDP Dst Port = TUNNEL_PORT (Geneve) */
	if (bpf_ntohs(udp->dest) != TUNNEL_PORT)
		test_error("expected outer udp dest port %d, got %d", TUNNEL_PORT, bpf_ntohs(udp->dest));

	struct genevehdr *gh = (void *)(udp + 1);
	if ((void *)(gh + 1) > data_end) test_fatal("geneve bounds");

	__u32 opt_bytes = gh->opt_len * 4;
	struct iphdr *inner_l3 = (void *)((char *)gh + sizeof(*gh) + opt_bytes);
	if ((void *)(inner_l3 + 1) > data_end) test_fatal("inner l3 bounds");

	assert_ip_equal(SRC_POD_IP, inner_l3->saddr);
	assert_ip_equal(DST_POD_IP, inner_l3->daddr);

	if (inner_l3->protocol != IPPROTO_TCP)
		test_error("expected inner protocol TCP, got %d", inner_l3->protocol);

	struct tcphdr *inner_l4 = (void *)(inner_l3 + 1);
	if ((void *)(inner_l4 + 1) > data_end) test_fatal("inner l4 bounds");

	if (bpf_ntohs(inner_l4->source) != SRC_PORT)
		test_error("expected inner src port %d, got %d", SRC_PORT, bpf_ntohs(inner_l4->source));
	if (bpf_ntohs(inner_l4->dest) != DST_PORT)
		test_error("expected inner dst port %d, got %d", DST_PORT, bpf_ntohs(inner_l4->dest));

	test_finish();
}

/*
 * Case 3: Pod to Pod on Remote VM
 * Two layers of tunnel lookup.
 */
PKTGEN("tc", "pod_to_remote_vm")
int pod_to_remote_vm_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);
	if (!pktgen__push_ethhdr(&builder)) return TEST_ERROR;
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);
	if (!l3) return TEST_ERROR;
	l3->saddr = SRC_POD_IP;
	l3->daddr = DST_REMOTE_VM_POD_IP;
	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4) return TEST_ERROR;
	l4->source = bpf_htons(SRC_PORT);
	l4->dest = bpf_htons(DST_PORT);

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data))) return TEST_ERROR;
	pktgen__finish(&builder);
	return TEST_PASS;
}

SETUP("tc", "pod_to_remote_vm")
int pod_to_remote_vm_setup(struct __ctx_buff *ctx)
{
	add_allow_all_egress_policy();
	struct endpoint_key src_pod_ep_key = { .family = ENDPOINT_KEY_IPV4, .ip4 = SRC_POD_IP };
	struct endpoint_info src_pod_ep_value = { .ifindex = LXC_INDEX, .lxc_id = TEST_LXC_ID };
	map_update_elem(&ENDPOINTS_MAP, &src_pod_ep_key, &src_pod_ep_value, BPF_ANY);

	/* 1. Pod on VM -> Tunnel = VM IP */
	struct ipcache_key pod_key = { .lpm_key = { .prefixlen = 32 }, .family = ENDPOINT_KEY_IPV4, .ip4 = DST_REMOTE_VM_POD_IP };
	struct remote_endpoint_info pod_val = { .sec_identity = 300, .tunnel_endpoint = bpf_htonl(DST_REMOTE_VM_IP) };
	map_update_elem(&IPCACHE_MAP, &pod_key, &pod_val, BPF_ANY);

	/* 2. VM IP -> Tunnel = Infra Node IP */
	struct ipcache_key vm_key = { .lpm_key = { .prefixlen = 32 }, .family = ENDPOINT_KEY_IPV4, .ip4 = DST_REMOTE_VM_IP };
	struct remote_endpoint_info vm_val = { .sec_identity = 400, .tunnel_endpoint = bpf_htonl(DST_INFRA_NODE_IP) };
	map_update_elem(&IPCACHE_MAP, &vm_key, &vm_val, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	return TEST_ERROR;
}

CHECK("tc", "pod_to_remote_vm")
int pod_to_remote_vm_check(struct __ctx_buff *ctx)
{
	test_init();
	void *data = (void*)(long) ctx_data(ctx);
	void *data_end = (void *)(long) ctx->data_end;

	__u32 *status_code = data;
	if ((void*)(status_code + 1) > data_end) test_fatal("bounds");
#if GOOGLE_IPSEC_MODE == 1
	if (*status_code != CTX_ACT_OK)
		test_error("expected OK, got %d", *status_code);
#else
	if (*status_code != CTX_ACT_REDIRECT)
		test_error("expected redirect, got %d", *status_code);
#endif

	struct ethhdr *outer_l2 = (void *)(status_code + 1);
	struct iphdr *outer_l3 = (void *)(outer_l2 + 1);
	if ((void *)(outer_l3 + 1) > data_end) test_fatal("outer l3 bounds");

	/* Expect Dst = DST_INFRA_NODE_IP (from second lookup) */
	assert_ip_equal(DST_INFRA_NODE_IP, bpf_ntohl(outer_l3->daddr));
	assert_ip_equal(IPV4_DIRECT_ROUTING, outer_l3->saddr); /* SRC_NODE_IP */

	/* Validate inner packet */
	struct udphdr *udp = (void *)(outer_l3 + 1);
	if ((void *)(udp + 1) > data_end) test_fatal("udp bounds");

	/* Outer UDP Dst Port = TUNNEL_PORT (Geneve) */
	if (bpf_ntohs(udp->dest) != TUNNEL_PORT)
		test_error("expected outer udp dest port %d, got %d", TUNNEL_PORT, bpf_ntohs(udp->dest));

	struct genevehdr *gh = (void *)(udp + 1);
	if ((void *)(gh + 1) > data_end) test_fatal("geneve bounds");

	__u32 opt_bytes = gh->opt_len * 4;
	struct iphdr *inner_l3 = (void *)((char *)gh + sizeof(*gh) + opt_bytes);
	if ((void *)(inner_l3 + 1) > data_end) test_fatal("inner l3 bounds");

	assert_ip_equal(DST_REMOTE_VM_POD_IP, inner_l3->daddr);
	assert_ip_equal(SRC_POD_IP, inner_l3->saddr);

	if (inner_l3->protocol != IPPROTO_TCP)
		test_error("expected inner protocol TCP, got %d", inner_l3->protocol);

	struct tcphdr *inner_l4 = (void *)(inner_l3 + 1);
	if ((void *)(inner_l4 + 1) > data_end) test_fatal("inner l4 bounds");

	if (bpf_ntohs(inner_l4->source) != SRC_PORT)
		test_error("expected inner src port %d, got %d", SRC_PORT, bpf_ntohs(inner_l4->source));
	if (bpf_ntohs(inner_l4->dest) != DST_PORT)
		test_error("expected inner dst port %d, got %d", DST_PORT, bpf_ntohs(inner_l4->dest));

	test_finish();
}
