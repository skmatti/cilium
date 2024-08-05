#pragma once

#include "lib/google/hooks_common.h"

/* Only apply strict egress policy when
 *	1. it's LXC traffic (if it's a container, it must not be in host network mode);
 *  2. enable-google-strict-egress-policy-validation is set to "true";
 *  3. egress gateway is enabled, as we rely on the egress bpf map;
 *  4. the container is not a multinic container, or it's not a macvtap virt-launcher container.
 */
#if defined(ENABLE_GOOGLE_STRICT_EGRESS_POLICY_VALIDATION) &&    \
	defined(IS_BPF_LXC) && defined(ENABLE_EGRESS_GATEWAY) && \
	(!defined(MULTI_NIC_DEVICE_TYPE) ||                      \
	 MULTI_NIC_DEVICE_TYPE != EP_DEV_TYPE_INDEX_MACVTAP)

# include "lib/common.h"
# include "lib/egress_gateway.h"

// Special egress IP used by strict egress policy validation entries.
// These egress gateway policy will have 255.255.255.254 as egress IP.
# define GOOGLE_STRICT_EGRESS_POLICY_EGRESS_IP bpf_htonl(0xfffffffe)

/*
 * Returns true when the given egress gateway policy is a special policy created
 * by the strict egress policy validation logic.
 */
static __always_inline bool google_is_strict_egress_policy(
	const struct egress_gw_policy_entry *egress_gw_policy)
{
	return egress_gw_policy &&
	       egress_gw_policy->egress_ip == GOOGLE_STRICT_EGRESS_POLICY_EGRESS_IP;
}

/*
 * Return CTX_ACT_OK if this packet can egress the cluster.
 * For traffic heading outside cluster, we should drop it if no egress gateway policy match is found.
 * This means the strict egress policy label is not defined for this pod.
 * For pods with strict egress policy label, we expect a egress gateway policy entry with BM node's IP as gateway IP,
 * and 255.255.255.254 as egress IP. If there is a legit egress gateway policy entry configured by user, that entry will
 * be returned instead.
 * When the special strict egress gateway policy is matched, egress_gw_request_needs_redirect() will be no-op
 * since the egress gateway is localhost.
 */
static __always_inline int google_validate_strict_egress_policy_access(
	const struct egress_gw_policy_entry *egress_gw_policy, enum ct_status st)
{
	if (egress_gw_policy)
		return CTX_ACT_OK;
	// Do not enforce egress policy on return traffic, this includes traffic initiated from outside the cluster
	// via load balancer and nodeport etc..
	if (st != CT_REPLY && st != CT_RELATED)
		return DROP_GOOGLE_NO_EGRESS_POLICY;
	return CTX_ACT_OK;
}

static __always_inline int google_strict_egress_policy_pre_ctr_egress_fwd4(
	struct goog_ctr_egress_fwd4_ctx *stage_ctx)
{
	struct egress_gw_policy_entry *egress_gw_policy;
	int ret;

	/* If the packet is destined to an entity inside the cluster,
	 * either EP or node, it should not be restircted by strict
	 * egress policy.
	 */
	if (identity_is_cluster(stage_ctx->dst_sec_identity))
		return HOOK_ACT_CONTINUE;

	egress_gw_policy = lookup_ip4_egress_gw_policy(
		ipv4_ct_reverse_tuple_saddr(stage_ctx->tuple),
		ipv4_ct_reverse_tuple_daddr(stage_ctx->tuple));
	ret = google_validate_strict_egress_policy_access(
		egress_gw_policy, stage_ctx->ct_status);
	if (IS_ERR(ret))
		return ret;
	return HOOK_ACT_CONTINUE;
}

#else

static __always_inline int google_strict_egress_policy_pre_ctr_egress_fwd4(
	struct goog_ctr_egress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif
