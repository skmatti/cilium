#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Flags Under Test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_GOOGLE_GENEVE
#define ENCAP_IFINDEX 4
#define ENABLE_GOOGLE_VPC
#define ENABLE_HOST_FIREWALL
#define ENABLE_EGRESS_GATEWAY

/* TURNS ON PERIMETER ELB */
#define GOOGLE_PERIMETER_FEATURES

/* Test Variables */
#define SRC_NODE_MAC	     mac_one
#define DST_NODE_MAC	     mac_two

#define SRC_NODE_IP	     v4_node_one
#define DST_NODE_IP	     v4_node_two

#define CLIENT_POD_IP	     v4_pod_one
#define BACKEND_POD_IP	     v4_pod_two

#define CLIENT_PORT	     5432
#define BACKEND_PORT	     8080

#define ELB_IP		     v4_svc_one
#define ELB_PORT	     443

#define CLIENT_POD_EGRESS_IP IPV4(1, 2, 3, 4)

#define PERIMETER_NODE_IP    v4_pod_three
#define EXTERNAL_SVC_IP	     v4_ext_one

/* Test Mocks */
struct mock_settings {
	bool is_stage_2;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct mock_settings));
	__uint(max_entries, 1);
} settings_map __section_maps_btf;

#define fib_lookup mock_fib_lookup

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
int mock_ctx_redirect(struct __sk_buff *ctx __maybe_unused,
		      int ifindex __maybe_unused,
		      __u32 flags __maybe_unused)
{
	__u32 key = 0;

	struct mock_settings *settings = map_lookup_elem(&settings_map, &key);

	if (!settings)
		return CTX_ACT_DROP;

	if (settings->is_stage_2)
		return CTX_ACT_OK;

	return CTX_ACT_REDIRECT;
}

#include "bpf_host.c"

#define FROM_NETDEV 0
#define TO_NETDEV   1

#include "lib/google_perimeter_elb.h"
#include "lib/dbg.h"
#include "lib/google/pktgen.h"
#include "tests/lib/egressgw_policy.h"

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[FROM_NETDEV] = &cil_from_netdev,
		[TO_NETDEV] = &cil_to_netdev,
	},
};

PKTGEN("tc", "stage_1_perimeter_elb_hairpin_traffic")
int perimeter_elb_hairpin_traffic_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	/* Ethernet Header */
	struct ethhdr *l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)SRC_NODE_MAC, (__u8 *)DST_NODE_MAC);

	/* IPv4 Header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_POD_IP;
	l3->daddr = ELB_IP;

	/* TCP Header */
	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = bpf_htons(CLIENT_PORT);
	l4->dest = bpf_htons(ELB_PORT);

	/* Packet Payload */
	void *data = pktgen__push_data(&builder,
				       default_data,
				       sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "stage_1_perimeter_elb_hairpin_traffic")
int perimeter_elb_hairpin_traffic_setup(struct __ctx_buff *ctx)
{
	/* Set up source pod identity */
	struct ipcache_key source_pod_cache_key = {
		.lpm_key.prefixlen = 32,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = CLIENT_POD_IP,
	};

	struct remote_endpoint_info source_pod_cache_value = {
		.sec_identity = 1111,
		.tunnel_endpoint = SRC_NODE_IP,
	};

	map_update_elem(&IPCACHE_MAP,
			&source_pod_cache_key,
			&source_pod_cache_value,
			BPF_ANY);

	/* Set up backend pod identity */
	struct ipcache_key dest_pod_cache_key = {
		.lpm_key.prefixlen = 32,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_POD_IP,
	};

	struct remote_endpoint_info dest_pod_cache_value = {
		.sec_identity = 2222,
		.tunnel_endpoint = DST_NODE_IP,
	};

	map_update_elem(&IPCACHE_MAP,
			&dest_pod_cache_key,
			&dest_pod_cache_value,
			BPF_ANY);

	/* Create LB for Backend */
	__u16 revnat_id = 1;

	struct lb4_key lb_svc_key = {
		.address = ELB_IP,
		.dport = bpf_htons(ELB_PORT),
		.scope = LB_LOOKUP_SCOPE_EXT,
	};

	struct lb4_service lb_svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
		.rev_nat_index = revnat_id,
	};

	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;

	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 125;

	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Create Entry for Rev NAT */
	struct lb4_reverse_nat revnat_value = {
		.address = bpf_htonl(ELB_IP),
		.port = bpf_htons(ELB_PORT),
	};

	map_update_elem(&LB4_REVERSE_NAT_MAP, &revnat_id, &revnat_value, BPF_ANY);

	/* Set up backend for ELB */
	struct lb4_backend backend = {
		.address = BACKEND_POD_IP,
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = BE_STATE_ACTIVE,
	};

	map_update_elem(&LB4_BACKEND_MAP,
			&lb_svc_value.backend_id,
			&backend,
			BPF_ANY);

	/* Set Up Egress Gateway */
	add_egressgw_policy_entry(CLIENT_POD_IP,
				  BACKEND_POD_IP,
				  32,
				  PERIMETER_NODE_IP,
				  CLIENT_POD_EGRESS_IP);

	/* Set Up Settings Map */
	__u32 settings_key = 0;
	struct mock_settings settings_value = { .is_stage_2 = false };

	map_update_elem(&settings_map, &settings_key, &settings_value, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	return TEST_ERROR;
}

CHECK("tc", "stage_1_perimeter_elb_hairpin_traffic")
int perimeter_elb_hairpin_traffic_check(struct __ctx_buff *ctx)
{
	test_init();

	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds.");

	__u32 *status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_error("expected status code to be redirect ('%d') but got '%d'",
			   CTX_ACT_REDIRECT, *status_code);

	/* Inspect Packet Headers */
	struct ethhdr *l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	struct iphdr *l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	struct tcphdr *l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	assert_ip_equal(CLIENT_POD_IP, l3->saddr);
	assert_ip_equal(BACKEND_POD_IP, l3->daddr);

	assert_num_equal(CLIENT_PORT, bpf_ntohs(l4->source));
	assert_num_equal(BACKEND_PORT, l4->dest);

	test_finish();
}

PKTGEN("tc", "stage_2_perimeter_elb_hairpin_traffic_to_netdev")
int perimeter_elb_hairpin_traffic_to_netdev_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	struct ethhdr *l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)SRC_NODE_MAC, (__u8 *)DST_NODE_MAC);

	/* IPv4 Header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_POD_IP;
	l3->daddr = BACKEND_POD_IP;

	/* TCP Header */
	struct tcphdr *l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = bpf_htons(CLIENT_PORT);
	l4->dest = bpf_htons(BACKEND_PORT);

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "stage_2_perimeter_elb_hairpin_traffic_to_netdev")
int perimeter_elb_hairpin_traffic_to_netdev_setup(struct __ctx_buff *ctx)
{
	/* Existing data structures should still be in place from stage 1 */

	/* Set Up Settings Map */
	__u32 settings_key = 0;
	struct mock_settings settings_value = { .is_stage_2 = true };

	map_update_elem(&settings_map, &settings_key, &settings_value, BPF_ANY);

	/* Call into TO_NETDEV */
	tail_call_static(ctx, entry_call_map, TO_NETDEV);

	return 0;
}

CHECK("tc", "stage_2_perimeter_elb_hairpin_traffic_to_netdev")
int perimeter_elb_hairpin_traffic_to_netdev_check(struct __ctx_buff *ctx)
{
	test_init();

	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds.");

	__u32 *status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_error("expected statuc code to be OK ('%d') but got '%d'",
			   CTX_ACT_OK, *status_code);

	struct ethhdr *l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	struct iphdr *l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	struct tcphdr *l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	assert_ip_equal(CLIENT_POD_EGRESS_IP, l3->saddr);
	assert_ip_equal(BACKEND_POD_IP, l3->daddr);

	assert_num_equal(BACKEND_PORT, bpf_ntohs(l4->dest));

	test_finish();
}
