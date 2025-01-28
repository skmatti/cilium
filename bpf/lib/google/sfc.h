#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "lib/google_sfc.h"
#include "lib/google_sfc_icmp.h"

#include "lib/google/plugin.h"

#ifdef ENABLE_GOOGLE_SERVICE_STEERING
enum {
	GOOG_SFC_EGRESS_IS_ENCAPPED = (1U << 0),
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} goog_sfc_egress_flags __section_maps_btf;

/**
 * goog_sfc_get_egress_flags - returns a pointer to the per-CPU egress flags for
 * SFC.
 */
static __always_inline __u32 *
goog_sfc_get_egress_flags(void)
{
	__u32 zero = 0;

	return map_lookup_elem(&goog_sfc_egress_flags, &zero);
}

/**
 * goog_sfc_reset_egress_state - reset per-CPU egress state.
 */
static __always_inline int
goog_sfc_reset_egress_state(void)
{
	__u32 *flags = goog_sfc_get_egress_flags();
	if (!flags)
		return DROP_GOOGLE_INVALID_FLAGS;

	*flags = 0;

	return HOOK_ACT_CONTINUE;
}

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
	__u32 *flags;
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
		flags = goog_sfc_get_egress_flags();
		if (!flags)
			return DROP_GOOGLE_INVALID_FLAGS;
		*flags |= GOOG_SFC_EGRESS_IS_ENCAPPED;
	}

	return HOOK_ACT_CONTINUE;
}

/**
 * goog_sfc_maybe_skip_egress_policy - skip egress policy if the packet is
 * encapped. Runs before CTR_EGRESS_POL4.
 */
static __always_inline int
goog_sfc_maybe_skip_egress_policy(void)
{
	__u32 *flags;

	flags = goog_sfc_get_egress_flags();
	if (!flags)
		return DROP_GOOGLE_INVALID_FLAGS;
	return (*flags & GOOG_SFC_EGRESS_IS_ENCAPPED) ?
	       HOOK_ACT_SKIP : HOOK_ACT_CONTINUE;
}

/**
 * goog_sfc_maybe_encap_new - check if outgoing packet needs to be encapsulated
 * and sent to an SFC. If so, encapsulate and reprocess it so that load
 * balancing logic can forward the packet to the right SFC backend. Runs before
 * CTR_EGRESS_FWD4.
 *
 * @ctx: tc context
 * @stage_ctx: stage context
 */
static __always_inline int
goog_sfc_maybe_encap_new(struct __ctx_buff *ctx,
			 struct goog_ctr_egress_fwd4_ctx *stage_ctx)
{
	struct redirect_info redir = {};
	__u32 *flags;
	int ret;

	flags = goog_sfc_get_egress_flags();
	if (!flags)
		return DROP_GOOGLE_INVALID_FLAGS;

	if (*flags & GOOG_SFC_EGRESS_IS_ENCAPPED)
		return HOOK_ACT_CONTINUE;

	ret = sfc_select4(ctx, stage_ctx->ip4, true, &redir);
	if (IS_ERR(ret))
		return ret;
	if (redir.path) {
		ret = sfc_encap(ctx, stage_ctx->ip4, &redir);
		if (unlikely(ret == DROP_FRAG_NEEDED))
			return sfc_redirect_icmp4(ctx, stage_ctx->ip4,
						  stage_ctx->rev_nat_index);
		if (IS_ERR(ret))
			return ret;
		*flags |= GOOG_SFC_EGRESS_IS_ENCAPPED;
		return goog_ctr_reprocess((union goog_ctr_stage_hook_ctx *)stage_ctx);
	}

	return HOOK_ACT_CONTINUE;
}
#else
static __always_inline int
goog_sfc_reset_egress_state(void)
{
	return HOOK_ACT_CONTINUE;
}

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

static __always_inline int
goog_sfc_maybe_skip_egress_policy(void)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
goog_sfc_maybe_encap_new(struct __ctx_buff *ctx __maybe_unused,
			 struct goog_ctr_egress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}
#endif
