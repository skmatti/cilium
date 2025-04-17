#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_GOOGLE_GENEVE
#define ENCAP_IFINDEX 4
#define ENABLE_GOOGLE_VPC
#define ENABLE_HOST_FIREWALL
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_EGRESS_GATEWAY_COMMON

/* TURNS ON PERIMETER ELB */
#define GOOGLE_PERIMETER_FEATURES

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte eth hdr */
#define ETH_HLEN 14
#define HAVE_LPM_TRIE_MAP_TYPE

#define CLIENT_IP	v4_ext_one
#define CLIENT_PORT	__bpf_htons(81)

#define ELB_IP		v4_svc_three
#define ELB_PORT	__bpf_htons(80)

#define BACKEND_IP	v4_pod_one
#define BACKEND_PORT	__bpf_htons(8080)

#define BACKEND_NODE_IP v4_node_one

static volatile const __u8 *client_mac = mac_one;

/* this matches the default node_config.h: */
static volatile const __u8 lb_mac[ETH_ALEN] = {
	0xce, 0x72, 0xa7, 0x03, 0x88, 0x56
};

static volatile const __u8 *remote_backend_mac = mac_five;

#define fib_lookup mock_fib_lookup

long mock_fib_lookup(__maybe_unused void *ctx,
		     struct bpf_fib_lookup *params,
		     __maybe_unused int plen,
		     __maybe_unused __u32 flags)
{
	if (params->ipv4_dst == BACKEND_IP) {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac,
				     (__u8 *)remote_backend_mac, ETH_ALEN);
	} else {
		__bpf_memcpy_builtin(params->smac, (__u8 *)lb_mac, ETH_ALEN);
		__bpf_memcpy_builtin(params->dmac, (__u8 *)client_mac, ETH_ALEN);
	}

	params->ifindex = 0;

	return 0;
}

/* Data shared between tests */
struct shared_data {
	__be16 nat_source_port;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct shared_data));
	__uint(max_entries, 1);
} settings_map __section_maps_btf;

#include "bpf_host.c"

#define FROM_NETDEV 0
#define TO_NETDEV   1

#define assert_ip_equal(expected_ip, result_ip)                                    \
	({                                                                       \
		if ((expected_ip) != (result_ip)) {                                    \
			__u32 exp1 = ((expected_ip) >> 24) & 0xFF;                  \
			__u32 exp2 = ((expected_ip) >> 16) & 0xFF;                  \
			__u32 exp3 = ((expected_ip) >> 8) & 0xFF;                   \
			__u32 exp4 = ((expected_ip)) & 0xFF;                        \
			__u32 recv1 = ((result_ip) >> 24) & 0xFF;                   \
			__u32 recv2 = ((result_ip) >> 16) & 0xFF;                   \
			__u32 recv3 = ((result_ip) >> 8) & 0xFF;                    \
			__u32 recv4 = ((result_ip)) & 0xFF;                         \
			test_log("line %d: ip address not equal", __LINE__);     \
			test_fatal("-- expected: %d.%d.%d.%d  got: %d.%d.%d.%d", \
				   exp4, exp3, exp2, exp1, recv4, recv3,         \
				   recv2, recv1);                                \
		}                                                                \
	})

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

PKTGEN("tc", "elb_arrival_traffic")
int elb_arrival_traffic_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Ethernet Header */
	struct ethhdr *l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* IPv4 header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = ELB_IP;

	/* TCP Header */
	struct tcphdr *l4 = pktgen__push_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = ELB_PORT;

	/* Packet Payload */
	void *data =
		pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "elb_arrival_traffic")
int elb_arrival_traffic_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Register fake LB backend matching our packet. */
	struct lb4_key lb_svc_key = {
		.address = ELB_IP,
		.dport = ELB_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};

	/* Create a service with only one backend */
	struct lb4_service lb_svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
		.rev_nat_index = revnat_id,
	};

	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* We need tp register both in the external and internal scope for the
	 * packet to be redirected to ta neighboring nodes
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_INT;

	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* A backend between 1 and .count is chosen, since we have only one backend
	 * it is always backend_slot 1. Point it to backend_id 124.
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	lb_svc_key.backend_slot = 1;

	lb_svc_value.backend_id = 125;

	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* Insert a reverse NAT entry for the above service */
	struct lb4_reverse_nat revnat_value = {
		.address = ELB_IP,
		.port = ELB_PORT,
	};

	map_update_elem(&LB4_REVERSE_NAT_MAP, &revnat_id, &revnat_value, BPF_ANY);

	/* Set up local backend for the service */
	struct lb4_backend backend = {
		.address = BACKEND_IP,
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = BE_STATE_ACTIVE,
	};

	map_update_elem(&LB4_BACKEND_MAP,
			&lb_svc_value.backend_id,
			&backend,
			BPF_ANY);

	/* Set up ipcache */
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = 32,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};
	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = BACKEND_NODE_IP,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	tail_call_static(ctx, entry_call_map, FROM_NETDEV);

	return TEST_ERROR;
}

CHECK("tc", "elb_arrival_traffic")
int elb_arrival_traffic_test(const struct __ctx_buff *ctx)
{
	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT)
		test_fatal("expected status code to be REDIRECT ('%d') but got '%d'",
			   CTX_ACT_REDIRECT, *status_code)

			/* Inspect Packet Headers */
			l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* Ensure that src ip is unchanged */
	assert_ip_equal(CLIENT_IP, l3->saddr);

	/* Ensure that destination IP matches backend IP */
	assert_ip_equal(BACKEND_IP, l3->daddr);

	__u32 key = 0;
	struct shared_data *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		settings->nat_source_port = l4->source;

	test_finish();
}

PKTGEN("tc", "elb_return_traffic")
int elb_return_traffic_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Ethernet Header */
	struct ethhdr *l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)remote_backend_mac, (__u8 *)lb_mac);

	/* IPv4 header */
	struct iphdr *l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->saddr = BACKEND_IP;
	l3->daddr = CLIENT_IP;

	/* TCP Header */
	struct tcphdr *l4 = pktgen__push_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = BACKEND_PORT;

	__u32 key = 0;
	struct shared_data *settings = map_lookup_elem(&settings_map, &key);

	if (settings)
		l4->dest = settings->nat_source_port;

	/* Packet Payload */
	void *data =
		pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "elb_return_traffic")
int elb_return_traffic_setup(struct __ctx_buff *ctx)
{
	tail_call_static(ctx, entry_call_map, TO_NETDEV);

	return TEST_ERROR;
}

CHECK("tc", "elb_return_traffic")
int elb_return_traffic_check(const struct __ctx_buff *ctx)
{
	test_init();

	void *data, *data_end;
	__u32 *status_code;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_OK)
		test_fatal("expected status code to be CTX_ACT_OK ('%d') but got '%d'",
			   CTX_ACT_OK, *status_code)

			if (data + sizeof(__u32) >
			    data_end) test_fatal("status code out of bounds");

	l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(struct ethhdr) > data_end)
		test_fatal("l2 out of bounds");

	l3 = (void *)l2 + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	l4 = (void *)l3 + sizeof(struct iphdr);

	if ((void *)l4 + sizeof(struct tcphdr) > data_end)
		test_fatal("l4 out of bounds");

	/* Ensure that the source IP has been changed to be the ELB IP */
	assert_ip_equal(ELB_IP, l3->saddr);

	/* Ensure that the destination IP has not changed */
	assert_ip_equal(CLIENT_IP, l3->daddr);

	/* Ensure that the source port has been changed to be the ELB port */
	if (l4->source != ELB_PORT)
		test_fatal("src port does not match ELB port");

	/* Ensure that the destination port has not changed */
	if (l4->dest != CLIENT_PORT)
		test_fatal("destination port does not match the client port");

	test_finish();
}
