#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

#define LXC_IPV4 (__be32)v4_pod_one

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_IPV4
#define MULTI_NIC_DEVICE_TYPE EP_DEV_TYPE_INDEX_MULTI_NIC_VETH
#define ENABLE_GOOGLE_MULTI_NIC
#define SRC_IP v4_pod_one
#define DEST_IP v4_pod_two
#define DEST_IFINDEX 5
#define DEST_LXC_ID 200
#define DEST_MULTINIC_ID 201
#define SECCTX_FROM_IPCACHE 1
#define TUNNEL_MODE 1
#define ENABLE_GOOGLE_VPC 1
#define ENCAP_IFINDEX 4
#define ENABLE_ROUTING 1
#define FRONTEND_IP_LOCAL v4_svc_one
#define FRONTEND_IP_REMOTE v4_svc_two
#define BACKEND_IP_LOCAL v4_pod_three
#define BACKEND_IP_REMOTE	IPV4(192, 168, 0, 4)
#define CLIENT_PORT __bpf_htons(111)
#define FRONTEND_PORT tcp_svc_one
#define BACKEND_PORT __bpf_htons(8080)
#define BACKEND_NODE_IP_REMOTE v4_node_one
#define HAVE_LPM_TRIE_MAP_TYPE
#define SRC_NETWORK_ID NETWORK_ID
#define DEV_INDEX 10

/* this matches the default node_config.h: */
static volatile const __u8 *node_mac = mac_three;
static volatile const __u8 *local_backend_mac = mac_four;
static volatile const __u8 *client_mac = mac_one;
static volatile const __u8 *server_mac = mac_two;

__section("mock-handle-policy")
int mock_handle_policy_redirect(struct __ctx_buff *ctx __maybe_unused)
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
		[DEST_LXC_ID] = &mock_handle_policy_redirect,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic
static __always_inline __maybe_unused void
mock_tail_call_dynamic(struct __ctx_buff *ctx __maybe_unused,
		       const void *map __maybe_unused, __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#include "bpf_lxc.c"

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

static void setup_policy_and_endpoint(__u32 ip, bool addMultinic)
{
	// Allow all egress traffic
	add_allow_all_egress_policy();

	// Prepare the endpoint key and value
	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = ip,
	};
	struct endpoint_info ep_value = {
		.ifindex = DEST_IFINDEX,
		.lxc_id = DEST_LXC_ID,
	};

	// Copy MAC address to endpoint
	memcpy(&ep_value.mac, (__u8 *)local_backend_mac, ETH_ALEN);
	memcpy(&ep_value.node_mac, (__u8 *)node_mac, ETH_ALEN);

	// Update the endpoint map with this key-value pair
	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	if (addMultinic) {
		// initialize multi_nic_dev_key and multi_nic_dev_info to ensure
		// padding are zeroed which could cause verifier failure.
		struct multi_nic_dev_key __maybe_unused key = {0};
		struct multi_nic_dev_info __maybe_unused multinic_info = {0};
		multinic_info.ifindex = DEV_INDEX;
		multinic_info.ep_id = DEST_MULTINIC_ID;
		multinic_info.net_id = SRC_NETWORK_ID;

		memcpy(&key.mac, (__u8 *)local_backend_mac, sizeof(key.mac));
		map_update_elem(&MULTI_NIC_DEV_MAP, &key, &multinic_info, BPF_ANY);
	}
}

/* Packet generation function that takes a destination IP as an argument */
int google_multinic_pktgen(struct __ctx_buff *ctx, __u32 dest_ip)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)server_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = SRC_IP;
	l3->daddr = dest_ip;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = FRONTEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));
	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

// Test packet from multinic veth to pod network via local delivery
PKTGEN("tc", "google_multinic_veth_to_pod")
int google_multinic_veth_to_pod_pktgen(struct __ctx_buff *ctx)
{
	return google_multinic_pktgen(ctx, DEST_IP);
}

SETUP("tc", "google_multinic_veth_to_pod")
int google_multinic_veth_to_pod_setup(struct __ctx_buff *ctx)
{
	setup_policy_and_endpoint(DEST_IP, false);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_multinic_veth_to_pod")
int google_multinic_veth_to_pod_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	// Ensure IPv4 header are not altered.
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != SRC_IP)
		test_fatal("src IP was not changed");

	if (l3->daddr != DEST_IP)
		test_fatal("dest IP was not changed");

	test_finish();
}

// Test packet from multinic veth to multinic veth in the same network
PKTGEN("tc", "google_multinic_veth_to_veth_succeed")
int google_multinic_veth_to_veth_succeed_pktgen(struct __ctx_buff *ctx)
{
	return google_multinic_pktgen(ctx, DEST_IP);
}

SETUP("tc", "google_multinic_veth_to_veth_succeed")
int google_multinic_veth_to_veth_succeed_setup(struct __ctx_buff *ctx)
{
    setup_policy_and_endpoint(DEST_IP, true);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_multinic_veth_to_veth_succeed")
int google_multinic_veth_to_veth_succeed_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	// Ensure IPv4 header are not altered.
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != SRC_IP)
		test_fatal("src IP was not changed");

	if (l3->daddr != DEST_IP)
		test_fatal("dest IP was not changed");

	test_finish();
}

// Test packet from multinic veth to service matching to a local backend
PKTGEN("tc", "google_multinic_veth_to_service_local")
int google_multinic_veth_to_service_local_pktgen(struct __ctx_buff *ctx)
{
	return google_multinic_pktgen(ctx, FRONTEND_IP_LOCAL);
}

SETUP("tc", "google_multinic_veth_to_service_local")
int google_multinic_veth_to_service_local_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Register a fake LB backend matching our packet. */
	struct lb4_key lb_svc_key = {
		.address = FRONTEND_IP_LOCAL,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	/* Create a service with only one backend */
	struct lb4_service lb_svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
		.rev_nat_index = revnat_id,
	};
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	/* We need to register both in the external and internal scopes for the
	 * packet to be redirected to a neighboring node
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* A backend between 1 and .count is chosen, since we have only one backend
	 * it is always backend_slot 1. Point it to backend_id 124.
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 124;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	// Set up local backend for the service
	struct lb4_backend backend = {
		.address = BACKEND_IP_LOCAL,
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = BE_STATE_ACTIVE,
	};
	map_update_elem(&LB4_BACKEND_MAP, &lb_svc_value.backend_id, &backend, BPF_ANY);

	setup_policy_and_endpoint(BACKEND_IP_LOCAL, false);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_multinic_veth_to_service_local")
int google_multinic_veth_to_service_local_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	// Ensure IPv4 header are not altered.
	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	if (l3->saddr != SRC_IP)
		test_fatal("src IP was not changed");

	if (l3->daddr != BACKEND_IP_LOCAL)
		test_fatal("dest IP was not changed");

	test_finish();
}

// Test packet from multinic veth to service matching to a remote backend
PKTGEN("tc", "google_multinic_veth_to_service_remote")
int google_multinic_veth_to_service_remote_pktgen(struct __ctx_buff *ctx)
{
	return google_multinic_pktgen(ctx, FRONTEND_IP_REMOTE);
}

SETUP("tc", "google_multinic_veth_to_service_remote")
int google_multinic_veth_to_service_remote_setup(struct __ctx_buff *ctx)
{
	__u16 revnat_id = 1;

	/* Register a fake LB backend matching our packet. */
	struct lb4_key lb_svc_key = {
		.address = FRONTEND_IP_REMOTE,
		.dport = FRONTEND_PORT,
		.scope = LB_LOOKUP_SCOPE_EXT,
	};
	/* Create a service with only one backend */
	struct lb4_service lb_svc_value = {
		.count = 1,
		.flags = SVC_FLAG_ROUTABLE,
		.rev_nat_index = revnat_id,
	};
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);
	/* We need to register both in the external and internal scopes for the
	 * packet to be redirected to a neighboring node
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_INT;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	/* A backend between 1 and .count is chosen, since we have only one backend
	 * it is always backend_slot 1. Point it to backend_id 125.
	 */
	lb_svc_key.scope = LB_LOOKUP_SCOPE_EXT;
	lb_svc_key.backend_slot = 1;
	lb_svc_value.backend_id = 125;
	map_update_elem(&LB4_SERVICES_MAP_V2, &lb_svc_key, &lb_svc_value, BPF_ANY);

	// Set up remote backend for the service
	struct lb4_backend backend = {
		.address = BACKEND_IP_REMOTE,
		.port = BACKEND_PORT,
		.proto = IPPROTO_TCP,
		.flags = BE_STATE_ACTIVE,
	};
	map_update_elem(&LB4_BACKEND_MAP, &lb_svc_value.backend_id, &backend, BPF_ANY);

	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = 32,
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP_REMOTE,
	};
	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = BACKEND_NODE_IP_REMOTE,
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	add_allow_all_egress_policy();

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_multinic_veth_to_service_remote")
int google_multinic_veth_to_service_remote_check(__maybe_unused const struct __ctx_buff *ctx)
{
	void *data;
	void *data_end;
	__u32 *status_code;
	struct iphdr *l3;

	test_init();

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	assert(*status_code == TC_ACT_REDIRECT);

	l3 = data + sizeof(__u32) + sizeof(struct ethhdr);

	if ((void *)l3 + sizeof(struct iphdr) > data_end)
		test_fatal("l3 out of bounds");

	// // destination IP should be changed to the remote node IP
	// if (l3->daddr != BACKEND_NODE_IP_REMOTE)
	// 	test_fatal("dest IP was not changed to remote node IP");

	// TODO(b/344899787): Correct the test expecation after VPC change is merged.
	// destination IP should be changed to the remote node IP
	// after merging GOOGLE VPC datapath change.
	if (l3->daddr != BACKEND_IP_REMOTE)
		test_fatal("dest IP should be remote node IP after VPC datapath change");

	test_finish();
}
