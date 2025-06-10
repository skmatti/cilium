#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "lib/google_sfc.h"
#include "lib/google_sfc_icmp.h"

#include "lib/google/plugin.h"

#ifdef ENABLE_GOOGLE_SERVICE_STEERING

/**
 * Cilium's is_valid_lxc_src_ipv4 function accepts a (struct iphdr *), but with
 * SFC enabled, we defer SIP validation until after egress policy enforcement
 * by simply preserving the original SIP in a per-CPU array, so we need a
 * function that simply accepts a __be32. Since the logic inside the original
 * is_valid_lxc_src_ipv4 is basically a one-liner, just copy it here and create
 * our own version that takes the SIP as a parameter directly.
 */
#ifdef ENABLE_SIP_VERIFICATION
static __always_inline
int goog_sfc_is_valid_lxc_src_ipv4(__be32 sip)
{
	return sip == LXC_IPV4;
}
#else /* ENABLE_SIP_VERIFICATION */
static __always_inline
int goog_sfc_is_valid_lxc_src_ipv4(__be32 sip __maybe_unused)
{
	return 1;
}
#endif /* ENABLE_SIP_VERIFICATION */

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __be32);
	__uint(max_entries, 1);
} goog_sfc_orig_sip __section_maps_btf;

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
 * goog_sfc_save_sip - save sip to a per-CPU map.
 *
 * @sip: the source IP.
 */
static __always_inline int
goog_sfc_save_sip(__be32 sip)
{
	__u32 zero = 0;

	return map_update_elem(&goog_sfc_orig_sip, &zero, &sip, 0) ?
	       DROP_INVALID_SIP : 0;
}

/**
 * goog_sfc_restore_sip - restore SIP that was previously saved with
 * goog_sfc_save_sip.
 *
 * @sip: destination for the source IP.
 */
static __always_inline int
goog_sfc_restore_sip(__be32 *sip)
{
	__be32 *sip_ptr;
	__u32 zero = 0;

	sip_ptr = map_lookup_elem(&goog_sfc_orig_sip, &zero);
	if (!sip_ptr)
		return DROP_INVALID_SIP;
	*sip = *sip_ptr;
	return 0;
}

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
	int ret;

	if (!flags) {
		ret = DROP_GOOGLE_INVALID_FLAGS;
		goto out;
	}

	*flags = 0;

	ret = goog_sfc_save_sip(0);
	if (IS_ERR(ret))
		goto out;

	ret = HOOK_ACT_CONTINUE;
out:
	return ret;
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
	struct redirect_info redir = {};
	void *data, *data_end;
	__be32 inner_saddr;
	struct iphdr *ip4;
	__u32 *flags;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	inner_saddr = ip4->saddr;
	ret = sfc_existing_flow(ctx, ip4, &redir);
	if (IS_ERR(ret))
		return ret;
	if (redir.path) {
		ret = sfc_encap(ctx, ip4, &redir);
		if (unlikely(ret == DROP_FRAG_NEEDED))
			return sfc_redirect_icmp4(ctx, ip4, 0);
		if (IS_ERR(ret))
			return ret;

		stage_ctx->sip_override = inner_saddr;
		flags = goog_sfc_get_egress_flags();
		if (!flags)
			return DROP_GOOGLE_INVALID_FLAGS;
		*flags |= GOOG_SFC_EGRESS_IS_ENCAPPED;
	}

	stage_ctx->disable_sip_validation = true;
	ret = goog_sfc_save_sip(inner_saddr);
	if (IS_ERR(ret))
		return ret;

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
	void *data, *data_end;
	struct iphdr *ip4;
	__be32 orig_sip;
	__u32 *flags;
	int ret;

	flags = goog_sfc_get_egress_flags();
	if (!flags)
		return DROP_GOOGLE_INVALID_FLAGS;

	if (*flags & GOOG_SFC_EGRESS_IS_ENCAPPED)
		goto skip_validate_sip;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	ret = sfc_select4(ctx, ip4, true, &redir);
	if (IS_ERR(ret))
		return ret;
	if (redir.path) {
		ret = sfc_encap(ctx, ip4, &redir);
		if (unlikely(ret == DROP_FRAG_NEEDED))
			return sfc_redirect_icmp4(ctx, ip4,
						  stage_ctx->rev_nat_index);
		if (IS_ERR(ret))
			return ret;
		*flags |= GOOG_SFC_EGRESS_IS_ENCAPPED;
		return goog_ctr_reprocess((union goog_ctr_stage_hook_ctx *)stage_ctx);
	}

	ret = goog_sfc_restore_sip(&orig_sip);
	if (IS_ERR(ret))
		return ret;

	if (unlikely(!goog_sfc_is_valid_lxc_src_ipv4(orig_sip)))
		return DROP_INVALID_SIP;
skip_validate_sip:
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
