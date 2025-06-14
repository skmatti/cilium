#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

#define LXC_IPV4 (__be32)v4_pod_one
// #include "config_replacement.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_GOOGLE_VPC
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_MASQUERADE_IPV4
#define ENCAP
#define ENCAP_IFINDEX 0
#define ENABLE_EGRESS_GATEWAY_REDIRECT
#define ENABLE_GOOGLE_GENEVE
#define SECCTX_FROM_IPCACHE 1
#define DEST_IFINDEX 5
#define DEST_LXC_ID 200
#define HAVE_FIB_NEIGH 1

__section("mock-handle-policy")
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_OK;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
	.values = {
		[DEST_LXC_ID] = &mock_handle_policy,
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
#include "lib/egressgw.h"
#include "lib/policy.h"

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

/* Test that a packet matching an egress gateway policy on the perimeter cluster from-container
 * program gets redirected to the gateway node via endpoints map local delivery.
 */
PKTGEN("tc", "google_egressgw_local_ep")
int google_egressgw_local_delivery_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_REDIRECT,
		});
}

SETUP("tc", "google_egressgw_local_ep")
int google_egressgw_local_delivery_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, GATEWAY_NODE_IP, 0);

	/* Avoid policy drop */
	policy_add_egress_allow_all_entry();

	/* Add local endpoint to the ENDPOINTS_MAP*/
	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = GATEWAY_NODE_IP,
	};

	struct endpoint_info ep_value = {
		.ifindex = DEST_IFINDEX,
		.lxc_id = DEST_LXC_ID,
	};

	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_egressgw_local_ep")
int google_egressgw_local_delivery_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_OK,
	});

	policy_delete_egress_entry();
	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);

	/* Delete local endpoint from the ENDPOINTS_MAP*/
	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = GATEWAY_NODE_IP,
	};

	map_delete_elem(&ENDPOINTS_MAP, &ep_key);

	return ret;
}

/* Test that a packet matching an egress gateway policy from-container not on the perimeter cluster
 * program gets redirected to the gateway node via ipcache.
 */
PKTGEN("tc", "google_egressgw_remote_ep")
int google_egressgw_remote_ep_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_REDIRECT,
		});
}

SETUP("tc", "google_egressgw_remote_ep")
int google_egressgw_remote_ep_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, GATEWAY_NODE_IP, 0);

	/* Avoid policy drop */
	policy_add_egress_allow_all_entry();

	/* Add remote endpoint to the IPCACHE*/
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = GATEWAY_NODE_IP,
	};
	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233
	};
	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_egressgw_remote_ep")
int google_egressgw_remote_ep_check(const struct __ctx_buff *ctx)
{
	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = TC_ACT_REDIRECT,
	});

	policy_delete_egress_entry();
	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24);

	/* Delete remote endpoint from the IPCACHE_MAP*/
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = GATEWAY_NODE_IP,
	};

	map_delete_elem(&IPCACHE_MAP, &cache_key);

	return ret;
}

/* Test that a packet matching an egress gateway policy without a gateway on the
 * from-container program does not get redirected to the gateway node.
 */
PKTGEN("tc", "google_egressgw_skip_no_gateway_redirect")
int google_egressgw_skip_no_gateway_redirect_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx) {
			.test = TEST_REDIRECT_SKIP_NO_GATEWAY,
		});
}

SETUP("tc", "google_egressgw_skip_no_gateway_redirect")
int google_egressgw_skip_no_gateway_redirect_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32, EGRESS_GATEWAY_NO_GATEWAY, 0);

	/* Avoid policy drop */
	policy_add_egress_allow_all_entry();

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_egressgw_skip_no_gateway_redirect")
int google_egressgw_skip_no_gateway_redirect_check(const struct __ctx_buff *ctx)
{
	struct metrics_value *entry = NULL;
	struct metrics_key key = {};

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx) {
			.status_code = CTX_ACT_DROP,
	});
	if (ret != TEST_PASS)
		return ret;

	test_init();

	key.reason = (__u8)-DROP_NO_EGRESS_GATEWAY;
	key.dir = METRIC_EGRESS;
	entry = map_lookup_elem(&METRICS_MAP, &key);
	if (!entry)
		test_fatal("metrics entry not found");
	assert(entry->count == 1);

	policy_delete_egress_entry();
	del_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP, 32);

	test_finish();
}
