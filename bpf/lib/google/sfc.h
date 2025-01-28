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
#else
static __always_inline int
goog_sfc_maybe_decap(struct __ctx_buff *ctx __maybe_unused,
		     struct goog_ctr_ingress_ct4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}
#endif
