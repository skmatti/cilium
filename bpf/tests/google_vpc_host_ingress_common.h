/* TEST VALUES */
#define SRC_REMOTE_NODE_MAC mac_one
#define DST_LOCAL_NODE_MAC mac_two

#define SRC_REMOTE_NODE_IP v4_node_one
#define DST_LOCAL_NODE_IP v4_node_two
#define IPV4_DIRECT_ROUTING DST_LOCAL_NODE_IP

/* Remote Pod (Sender) */
#define SRC_REMOTE_POD_IP v4_pod_one

/* Local Pod (Receiver) */
#define DST_LOCAL_POD_IP v4_pod_two

/* Pod on VM Scenarios */
#define DST_VM_IP 0x0A0000FD /* 10.0.0.253 */
#define DST_POD_ON_VM_IP 0x0A000202

#define SRC_PORT 5000
#define DST_PORT 80

#define LXC_INDEX 10
#define TEST_LXC_ID 100

#define VM_INDEX 20
#define TEST_VM_ID 200


long mock_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags);
#define fib_lookup mock_fib_lookup

#include "pktgen.h"
#include "bpf_host.c"
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
	tuple.flags = TUPLE_F_IN; // Ingress flow

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
	__bpf_memcpy_builtin(params->smac, (__u8 *)DST_LOCAL_NODE_MAC, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)SRC_REMOTE_NODE_MAC, ETH_ALEN);

	return BPF_FIB_LKUP_RET_SUCCESS;
}

#define FROM_NETDEV 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
	},
};

#ifndef SKIP_POLICY_MAP
static __always_inline void add_allow_all_ingress_policy(void)
{
	struct policy_key policy_key = {
		.egress = 0, /* Ingress */
	};
	struct policy_entry policy_value = {
		.deny = 0,
	};
	map_update_elem(&POLICY_MAP, &policy_key, &policy_value, BPF_ANY);
}
#endif

/*
 * Case 1: Ingress to Local Pod
 * Outer: Remote Node -> Local Node (Geneve)
 * Inner: Remote Pod -> Local Pod
 * Expectation: Decap and Redirect to Local Pod
 */
PKTGEN("tc", "ingress_to_local_pod")
int ingress_to_local_pod_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	/* Geneve Header setup using google_pktgen helper */
	struct google_pktgen__genevehdr_params geneve_params = {
		.src_mac = (__u8 *)SRC_REMOTE_NODE_MAC,
		.dst_mac = (__u8 *)DST_LOCAL_NODE_MAC,
		.outer_src_ip = SRC_REMOTE_NODE_IP,
		.outer_dst_ip = DST_LOCAL_NODE_IP,
		.outer_src_port = 6081,
		.outer_dst_port = TUNNEL_PORT, /* 8472 usually */
		.direction = GENEVE_INGRESS_CLUSTER,
	};

	if (google_pktgen__push_genevehdr(&builder, geneve_params) != TEST_PASS)
		return TEST_ERROR;

	/* Inner Packet: IPv4 */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);
	if (!l3) return TEST_ERROR;
	l3->saddr = SRC_REMOTE_POD_IP;
	l3->daddr = DST_LOCAL_POD_IP;

	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4) return TEST_ERROR;
	l4->source = bpf_htons(SRC_PORT);
	l4->dest = bpf_htons(DST_PORT);

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data))) return TEST_ERROR;

	google_pktgen__finish_geneve_pkt(&builder);
	return TEST_PASS;
}

SETUP("tc", "ingress_to_local_pod")
int ingress_to_local_pod_setup(struct __ctx_buff *ctx)
{
	add_allow_all_ingress_policy();

	/* Local Pod Endpoint */
	struct endpoint_key ep_key = { .family = ENDPOINT_KEY_IPV4, .ip4 = DST_LOCAL_POD_IP };
	struct endpoint_info ep_value = { .ifindex = LXC_INDEX, .lxc_id = TEST_LXC_ID };
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "ingress_to_local_pod")
int ingress_to_local_pod_check(struct __ctx_buff *ctx)
{
	test_init();
	void *data = (void*)(long) ctx_data(ctx);
	void *data_end = (void *)(long) ctx->data_end;

	__u32 *status_code = data;
	if ((void*)(status_code + 1) > data_end) test_fatal("bounds");

	/* Expect Redirect to LXC */
	if (*status_code != CTX_ACT_REDIRECT)
		test_error("expected redirect, got %d", *status_code);

	/* Verify Outer Packet NOT in Conntrack */
	struct ipv4_ct_tuple outer_tuple = {};
	outer_tuple.nexthdr = IPPROTO_UDP;
	outer_tuple.daddr = DST_LOCAL_NODE_IP;
	outer_tuple.saddr = SRC_REMOTE_NODE_IP;
	outer_tuple.dport = bpf_htons(TUNNEL_PORT);
	outer_tuple.sport = bpf_htons(6081);
	outer_tuple.flags = TUPLE_F_IN;

	void *outer_ct = map_lookup_elem(&CT_MAP_ANY4, &outer_tuple);
	if (outer_ct) test_error("Outer Geneve packet found in CT map (unexpected)");

	/* Verify Packet Decapsulated (Inner headers should be at start) */
	/* Packet is decapsulated at this point, so we verify the inner headers (Layer 3).
	 * IP header should be at the start of the data.
	 */

	struct ethhdr *l2 = (void *)(status_code + 1);
	if ((void *)(l2 + 1) > data_end) test_fatal("l2 bounds");

	struct iphdr *l3 = (void *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end) test_fatal("l3 bounds");

	assert_ip_equal(SRC_REMOTE_POD_IP, l3->saddr);
	assert_ip_equal(DST_LOCAL_POD_IP, l3->daddr);

	test_finish();
}

/*
 * Case 1b: Ingress with Wrong UDP Port (Negative Test)
 * Outer: UDP 9999 (Not Geneve)
 * Expectation: No Decap, CT Entry Created
 */
PKTGEN("tc", "ingress_wrong_port")
int ingress_wrong_port_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	struct google_pktgen__genevehdr_params geneve_params = {
		.src_mac = (__u8 *)SRC_REMOTE_NODE_MAC,
		.dst_mac = (__u8 *)DST_LOCAL_NODE_MAC,
		.outer_src_ip = SRC_REMOTE_NODE_IP,
		.outer_dst_ip = DST_LOCAL_NODE_IP,
		.outer_src_port = 6081,
		.outer_dst_port = 9999, /* Wrong Port */
		.direction = GENEVE_INGRESS_CLUSTER,
	};

	if (google_pktgen__push_genevehdr(&builder, geneve_params) != TEST_PASS)
		return TEST_ERROR;

	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);
	if (!l3) return TEST_ERROR;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data))) return TEST_ERROR;

	google_pktgen__finish_geneve_pkt(&builder);
	return TEST_PASS;
}

SETUP("tc", "ingress_wrong_port")
int ingress_wrong_port_setup(struct __ctx_buff *ctx)
{
	add_allow_all_ingress_policy();
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "ingress_wrong_port")
int ingress_wrong_port_check(struct __ctx_buff *ctx)
{
	test_init();
	void *data = (void*)(long) ctx_data(ctx);
	void *data_end = (void *)(long) ctx->data_end;
	__u32 *status_code = data;

	if ((void*)(status_code + 1) > data_end) test_fatal("bounds");

	/* Expect CTX_ACT_OK (passed to stack as regular UDP) */
	if (*status_code != CTX_ACT_OK)
		test_error("expected OK, got %d", *status_code);

	/* Verify Packet NOT Decapsulated */
	/* We expect L3 to be the Outer IP */
	struct ethhdr *l2 = (void *)(status_code + 1);
	if ((void *)(l2 + 1) > data_end) test_fatal("l2 bounds");

	struct iphdr *l3 = (void *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end) test_fatal("l3 bounds");

	if (l3->protocol != IPPROTO_UDP)
		test_error("expected UDP protocol, got %d", l3->protocol);

	/* Check headers are preserved */
	assert_ip_equal(SRC_REMOTE_NODE_IP, l3->saddr);

	/* Check UDP dest port */
	struct udphdr *l4 = (void *)((void *)l3 + sizeof(struct iphdr)); // Assume no options
	if ((void *)(l4 + 1) > data_end) test_fatal("l4 bounds");

	if (l4->dest != bpf_htons(9999))
		test_error("expected dest port 9999, got %d", bpf_ntohs(l4->dest));

	test_finish();
}


/*
 * Case 2: Ingress to Pod on VM.
 * Outer: Remote Node -> Local Node (Geneve)
 * Inner: Remote Pod -> Pod on VM
 *
 * The "Pod on VM" is not a local endpoint of the Host. It is inside a VM running on this Host.
 * The Host acts as a router.
 *
 * Flow:
 * 1. Host decapsulates Geneve packet.
 * 2. Host looks up Inner logic (DST_POD_ON_VM_IP).
 *    - Not found in Local Endpoints.
 *    - Found in IPcache: Maps to Tunnel Endpoint = DST_VM_IP.
 * 3. Host looks up DST_VM_IP.
 *    - Found in Local Endpoints (The VM's interface).
 * 4. Result: Packet is redirected to the VM's interface.
 */

PKTGEN("tc", "ingress_to_pod_on_vm")
int ingress_to_pod_on_vm_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	struct google_pktgen__genevehdr_params geneve_params = {
		.src_mac = (__u8 *)SRC_REMOTE_NODE_MAC,
		.dst_mac = (__u8 *)DST_LOCAL_NODE_MAC,
		.outer_src_ip = SRC_REMOTE_NODE_IP,
		.outer_dst_ip = DST_LOCAL_NODE_IP,
		.outer_src_port = 6081,
		.outer_dst_port = TUNNEL_PORT,
		.direction = GENEVE_INGRESS_CLUSTER,
	};

	if (google_pktgen__push_genevehdr(&builder, geneve_params) != TEST_PASS)
		return TEST_ERROR;

	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);
	if (!l3) return TEST_ERROR;
	l3->saddr = SRC_REMOTE_POD_IP;
	l3->daddr = DST_POD_ON_VM_IP; /* To Pod on VM */

	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4) return TEST_ERROR;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data))) return TEST_ERROR;

	google_pktgen__finish_geneve_pkt(&builder);
	return TEST_PASS;
}

SETUP("tc", "ingress_to_pod_on_vm")
int ingress_to_pod_on_vm_setup(struct __ctx_buff *ctx)
{
	add_allow_all_ingress_policy();

	/* Setup IPcache for Pod -> VM */
	struct ipcache_key ip_key = { .lpm_key = { .prefixlen = 32 }, .family = ENDPOINT_KEY_IPV4, .ip4 = DST_POD_ON_VM_IP };
	struct remote_endpoint_info ip_val = { .sec_identity = 300, .tunnel_endpoint = DST_VM_IP };
	map_update_elem(&IPCACHE_MAP, &ip_key, &ip_val, BPF_ANY);

	/* Setup Endpoint for VM */
	struct endpoint_key ep_key = { .family = ENDPOINT_KEY_IPV4, .ip4 = DST_VM_IP };
	struct endpoint_info ep_value = { .ifindex = VM_INDEX, .lxc_id = TEST_VM_ID };
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "ingress_to_pod_on_vm")
int ingress_to_pod_on_vm_check(struct __ctx_buff *ctx)
{
	test_init();
	void *data = (void*)(long) ctx_data(ctx);
	void *data_end = (void *)(long) ctx->data_end;

	__u32 *status_code = data;
	if ((void*)(status_code + 1) > data_end) test_fatal("bounds");

	if (*status_code != CTX_ACT_REDIRECT)
		test_error("expected redirect, got %d", *status_code);

	/* Verify Packet Content */

	/* Inner Packet should still be intact (decap occurred) */
	struct ethhdr *l2 = (void *)(status_code + 1);
	if ((void *)(l2 + 1) > data_end) test_fatal("l2 bounds");

	struct iphdr *l3 = (void *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end) test_fatal("l3 bounds");
	assert_ip_equal(SRC_REMOTE_POD_IP, l3->saddr);
	assert_ip_equal(DST_POD_ON_VM_IP, l3->daddr);

	test_finish();
}
