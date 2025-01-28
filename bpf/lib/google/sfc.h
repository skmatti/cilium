#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "lib/google_sfc.h"
#include "lib/google_sfc_icmp.h"

#include "lib/google/plugin.h"

#ifdef ENABLE_GOOGLE_SERVICE_STEERING
/**
 * goog_sfc_maybe_decap - decapsulate incoming packet if necessary and deliver
 * to the container. Runs before CTR_INGRESS_CT4.
 *
 * @ctx: tc context
 * @stage_ctx: stage context
 */
static __always_inline int
goog_sfc_maybe_decap(struct __ctx_buff *ctx,
		     struct goog_ctr_ingress_ct4_ctx *stage_ctx)
{
	bool skip_conntrack = false;
	int ret;

	ret = try_sfc_decap(ctx, &skip_conntrack);
	if (IS_ERR(ret))
		return ret;
	if (skip_conntrack)
		return goog_ctr_deliver((union goog_ctr_stage_hook_ctx *)stage_ctx);

	return HOOK_ACT_CONTINUE;
}

/**
 * goog_sfc_maybe_encap_existing - encapsulate outgoing packet if this packet
 * belongs to an existing SFC flow. Runs before CTR_EGRESS_SVC4. Defers SIP
 * validation until CTR_EGRESS_FWD4.
 *
 * @ctx: tc context
 * @stage_ctx: stage context
 */
static __always_inline int
goog_sfc_maybe_encap_existing(struct __ctx_buff *ctx,
			      struct goog_ctr_egress_svc4_ctx *stage_ctx)
{
	__be32 inner_saddr = stage_ctx->ip4->saddr;
	struct redirect_info redir = {};
	int ret;

	ret = sfc_existing_flow(ctx, stage_ctx->ip4, &redir);
	if (IS_ERR(ret))
		return ret;
	if (redir.path) {
		ret = sfc_encap(ctx, stage_ctx->ip4, &redir);
		if (unlikely(ret == DROP_FRAG_NEEDED))
			return sfc_redirect_icmp4(ctx, stage_ctx->ip4, 0);
		if (IS_ERR(ret))
			return ret;

		stage_ctx->sip_override = inner_saddr;
	}

	return HOOK_ACT_CONTINUE;
}
#else
static __always_inline int
goog_sfc_maybe_decap(struct __ctx_buff *ctx __maybe_unused,
		     struct goog_ctr_ingress_ct4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
goog_sfc_maybe_encap_existing(struct __ctx_buff *ctx __maybe_unused,
			      struct goog_ctr_egress_svc4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}
#endif
