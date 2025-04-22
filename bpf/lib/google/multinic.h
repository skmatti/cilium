#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "hooks_common.h"

#include "lib/google_multinic.h"
#include "lib/google/plugin.h"

#ifdef ENABLE_GOOGLE_MULTI_NIC

#ifdef IS_BPF_HOST

static __always_inline int
goog_mn_maybe_deliver_to_ep(struct __ctx_buff *ctx,
			    struct goog_host_ingress_fwd4_ctx_common *stage_ctx)
{
	bool should_to_endpoint = false;
	void *data, *data_end;
	int ret;

	/* Mark the source IDENTITY as HOST if the packet is local-redirected
	 * for the multinic device before redirection to kernel.
	 *
	 * The ingress BPF program of the multinic device can correctly
	 * inherit the source IDENTITY to process the packet.
	 */
	if (unlikely(ctx_google_local_redirect(ctx)))
		ctx->mark = MARK_MAGIC_HOST;

	/* Here we enable the redirect datapath to deliver traffic from netdev
	 * to local L3 multi-nic endpoints, for which we either drop the packet
	 * if wrong device, or redirect it to the endpoint.
	 */
	ret = try_google_L3_fast_redirect(ctx, stage_ctx->secctx,
					  stage_ctx->ip4, &should_to_endpoint);
	if (should_to_endpoint)
		ret = HOOK_ACT_SKIP;
	else if (ret == CTX_ACT_OK)
		ret = HOOK_ACT_CONTINUE;

	if (!revalidate_data(ctx, &data, &data_end, &stage_ctx->ip4))
		ret = DROP_INVALID;

	return ret;
}

#endif /* IS_BPF_HOST */

#else

#ifdef IS_BPF_HOST

static __always_inline int
goog_mn_maybe_deliver_to_ep(struct __ctx_buff *ctx __maybe_unused,
			    struct goog_host_ingress_fwd4_ctx_common *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif /* IS_BPF_HOST */

#endif /* ENABLE_GOOGLE_MULTI_NIC */

#ifdef MULTI_NIC_DEVICE_TYPE

static __always_inline
int goog_maybe_redirect_if_dhcp(struct __ctx_buff *ctx,
				struct goog_ctr_egress_svc4_ctx *stage_ctx)
{
	void *data, *data_end;
	int ret;

	/* Examine packet sourcing from multi NIC endpoint. */
	ret = redirect_if_dhcp(ctx, stage_ctx->ip4->protocol,
			       ETH_HLEN + ipv4_hdrlen(stage_ctx->ip4),
			       stage_ctx->ip4->saddr);

	if (!revalidate_data(ctx, &data, &data_end, &stage_ctx->ip4))
		return DROP_INVALID;

	if (ret != CTX_ACT_OK)
		return ret;

	return HOOK_ACT_CONTINUE;
}

#else

static __always_inline
int goog_maybe_redirect_if_dhcp(struct __ctx_buff *ctx __maybe_unused,
				struct goog_ctr_egress_svc4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif /* MULTI_NIC_DEVICE_TYPE */
