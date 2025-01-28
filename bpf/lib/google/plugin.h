#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "lib/common.h"
#include "lib/google/hooks_common.h"

/**
 * container_of - cast a member of a structure out to the containing structure
 *
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 */
#define container_of(ptr, type, member)                      \
({                                                           \
	const typeof( ((type *)0)->member ) *__mptr = (ptr); \
	(type *)((char *)__mptr - offsetof(type,member));    \
})

/**
 * parent_ctr_stage_ctx - get a pointer to the containing struct ctr_stage_ctx
 * for the inner_ctx.
 *
 * @inner_ct: pointer to the union ctr_stage_hook_ctx embedded in a struct
 *            ctr_stage_ctx.
 */
#define parent_ctr_stage_ctx(inner_ctx) \
	container_of(inner_ctx, struct goog_ctr_stage_ctx, stage_ctx)

/**
 * goog_ctr_deliver - deliver packet to the container. This does any work
 * necessary to deliver the packet to the container. Its return code should be
 * propagated and returned from the parent TC hook. Currently only supported for
 * these stages:
 * - CTR_INGRESS_CT4
 *
 * @ctx: pointer to the stage context.
 */
static __always_inline int
goog_ctr_deliver(union goog_ctr_stage_hook_ctx *ctx)
{
	struct goog_ctr_stage_ctx *stage_ctx = parent_ctr_stage_ctx(ctx);
	bool from_tunnel;
	bool from_host;
	int ifindex;

	/* Make sure this is invoked from a valid context. */
	switch (stage_ctx->curr) {
	case CTR_INGRESS_CT4:
		break;
	default:
		return DROP_UNROUTABLE;
	}

	if (stage_ctx->stage_ctx.goog_ctr_ingress_ct4_ctx.__cil_to_container)
		return CTX_ACT_OK;

	/* Mimic how ipv4_policy redircts to endpoint. */
	from_host = ctx_load_meta(stage_ctx->ctx, CB_FROM_HOST);
	from_tunnel = ctx_load_meta(stage_ctx->ctx, CB_FROM_TUNNEL);
	ifindex = ctx_load_meta(stage_ctx->ctx, CB_IFINDEX);

	if (ifindex)
		return redirect_ep(stage_ctx->ctx, ifindex, from_host, from_tunnel);

	return DROP_UNROUTABLE;
}

/**
 * goog_ctr_reprocess - jump back to the beginning of the TC program chain for
 * this packet. Currently only supported for these stages:
 * - CTR_EGRESS_SVC4:
 * - CTR_EGRESS_POL4:
 * - CTR_EGRESS_FWD4:
 *
 * @ctx: pointer to the stage context.
 */
static __always_inline int
goog_ctr_reprocess(union goog_ctr_stage_hook_ctx *ctx)
{
	struct goog_ctr_stage_ctx *stage_ctx = parent_ctr_stage_ctx(ctx);

	/* Make sure this is invoked from a valid context. */
	switch (stage_ctx->curr) {
	case CTR_EGRESS_SVC4:
	case CTR_EGRESS_POL4:
	case CTR_EGRESS_FWD4:
		return tail_call_internal(stage_ctx->ctx, CILIUM_CALL_IPV4_FROM_LXC,
								  stage_ctx->ext_err);
	default:
		return DROP_GOOGLE_INVALID_CONTEXT;
	}
}
