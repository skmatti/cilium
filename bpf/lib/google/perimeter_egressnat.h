#pragma once

#include "lib/google/hooks_common.h"

/* Only enable perimeter features in infra cluster
 */
#if defined(ENABLE_EGRESS_GATEWAY_REDIRECT)

#include "lib/common.h"
#include "lib/eps.h"
#include "lib/egress_gateway.h"
#include "lib/google/geneve.h"
#include "lib/google_perimeter_elb.h"
#include "lib/google/strict_egress_policy.h"

static __always_inline
int google_perimeter_egress_policy_pre_ctr_egress_fwd4(struct __ctx_buff *ctx __maybe_unused,
						       struct goog_ctr_egress_fwd4_ctx *stage_ctx)
{
	struct egress_gw_policy_entry *egress_gw_policy;
	struct google_ctmap_entry *egress_ct_info;
	struct endpoint_info *lep;
	struct iphdr *ip4;
	void *data, *data_end;
	struct trace_ctx trace = {};
	__u32 perimeter_gw_ip;

	if (identity_is_cluster(stage_ctx->dst_sec_identity))
		return HOOK_ACT_CONTINUE;

	egress_gw_policy = lookup_ip4_egress_gw_policy(ipv4_ct_reverse_tuple_saddr(stage_ctx->tuple),
						       ipv4_ct_reverse_tuple_daddr(stage_ctx->tuple));

	if (google_is_strict_egress_policy(egress_gw_policy))
		return HOOK_ACT_CONTINUE;

	if (!egress_gw_policy)
		return HOOK_ACT_CONTINUE;

	/* Attempt to retrieve the perimeter gateway IP from the Google CT map. */
	egress_ct_info = lookup_google_ctmap_entry(stage_ctx->tuple);
	if (egress_ct_info && egress_ct_info->egress_nat && egress_ct_info->ip4_addr != 0) {
		/* Use the gw ip from established connection to perform the redirect. */
		perimeter_gw_ip = egress_ct_info->ip4_addr;
	} else {
		/* For new connections, or if no CT entry exists
		 * determine the perimeter gateway IP from the `egress_gw_policy`.
		 */
		perimeter_gw_ip = egress_gw_policy->gateway_ip;
		update_google_ctmap_egress_gw_ip(stage_ctx->tuple, egress_gw_policy->gateway_ip);
	}

	/* If the packet is a reply or is related, it means that outside
	 * has initiated the connection, and so we should skip egress
	 * gateway, since an egress policy is only matching connections
	 * originating from a pod.
	 *
	 * The excpetion to the above decision is in the following case:
	 * For the egress gateway policy installed by TrafficSteering CR,
	 * egress_ip is always set to 0xffffffff (255.255.255.255).
	 * For the packet which is outside initiated, if egress_gw_policy has egress_ip
	 * set to 0xffffffff (255.255.255.255), we want this
	 * packet not to skip egress gateway and we want this packet to follow
	 * the egress gw policy and go back to the ANG/GNG node, before going
	 * back outside of the cluster.
	 */
	if ((stage_ctx->ct_status == CT_REPLY || stage_ctx->ct_status == CT_RELATED) && egress_gw_policy->egress_ip != 0xffffffff)
		return HOOK_ACT_CONTINUE;

	lep = __lookup_ip4_endpoint(perimeter_gw_ip);

	/* Handle Strict Egress Policy Case*/
	/* TODO: (b/439603456) take out when strict egress policy is using new map */
	if (lep && (lep->flags & ENDPOINT_F_HOST))
		return HOOK_ACT_CONTINUE;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	return google_perimeter__redirect_to_perimeter_gateway(ctx, ip4, &trace, perimeter_gw_ip);
}

#else

static __always_inline int google_perimeter_egress_policy_pre_ctr_egress_fwd4(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_ctr_egress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif
