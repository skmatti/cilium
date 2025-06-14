#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "lib/google/sfc.h"
#include "lib/google/multinic.h"
#include "lib/google/pip.h"
#include "lib/google/geneve.h"
#include "lib/google/vpc.h"
#include "lib/google/strict_egress_policy.h"
#include "lib/google/perimeter_egressnat.h"
#include "lib/google/plugin.h"
#include "lib/google_multinic.h"
#include "lib/google/google_perimeter_elb.h"

/**
 * This file contains hook implementations for hook points inside the container
 * datapath (bpf_lxc.c). Put Google code here. #include other Google code as
 * needed.
 *
 * NOTE: CONSULT THE DPV2 CORE TEAM BEFORE MODIFYING EXISTING HOOKS OR ADDING
 * NEW HOOK POINTS.
 */

/**
 * Container ingress hooks
 *  _____________________
 * |                     | cil_to_container (endpoint routes)
 * |  CTR_INGRESS_START  | handle_policy    (no endpoint routes)
 * |_____________________|
 *            |
 *   pre_ctr_ingress_ct4()
 *            |
 *  __________V__________
 * |                     |
 * |   CTR_INGRESS_CT4   | CILIUM_CALL_IPV4_CT_INGRESS
 * |_____________________|
 *            |
 *   pre_ctr_ingress_pol4()
 *            |
 *  __________V__________
 * |                     | tail_ipv4_to_endpoint (endpoint routes)
 * |  CTR_INGRESS_POL4   | tail_ipv4_policy      (no endpoint routes)
 * |_____________________|
 *            |
 *   pre_ctr_ingress_del4()
 *            |
 *  __________V__________
 * |                     | tail_ipv4_to_endpoint (endpoint routes)
 * |  CTR_INGRESS_DEL4   | tail_ipv4_policy      (no endpoint routes)
 * |_____________________|
 */
static __always_inline int
pre_ctr_ingress_ct4(struct __ctx_buff *ctx,
		    struct goog_ctr_ingress_ct4_ctx *stage_ctx)
{
	int ret = goog_sfc_maybe_decap(ctx, stage_ctx);
	if (ret != HOOK_ACT_CONTINUE)
		return ret;

	if (is_dst_endpoint_pip4(ctx))
		return CTX_ACT_OK;

	return HOOK_ACT_CONTINUE;
}

static __always_inline int
pre_ctr_ingress_pol4(struct __ctx_buff *ctx __maybe_unused,
		     struct goog_ctr_ingress_pol4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
pre_ctr_ingress_del4(struct __ctx_buff *ctx __maybe_unused,
		     struct goog_ctr_ingress_del4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

/**
 * Container egress hooks
 *  ____________________
 * |                    |
 * |  CTR_EGRESS_START  | cil_from_container
 * |____________________|
 *           |
 * pre_ctr_egress_start4()
 *           |
 *  _________V__________
 * |                    |
 * |  CTR_EGRESS_SVC4   | __per_packet_lb_svc_xlate_4
 * |____________________|
 *           |
 *  pre_ctr_egress_svc4()
 *           |
 *  _________V__________
 * |                    |
 * |  CTR_EGRESS_CT4    |
 * |____________________|
 *           |
 *  pre_ctr_egress_pol4()
 *           |
 *  _________V__________
 * |                    |
 * |  CTR_EGRESS_POL4   | handle_ipv4_from_lxc
 * |____________________|
 *           |
 *  pre_ctr_egress_fwd4()
 *           |
 *  _________V__________
 * |                    |
 * |  CTR_EGRESS_FWD4   | handle_ipv4_from_lxc
 * |____________________|
 */

static __always_inline int
pre_ctr_egress_start4(struct __ctx_buff *ctx __maybe_unused,
		      struct goog_ctr_egress_start4_ctx *stage_ctx __maybe_unused)
{
	int ret = goog_geneve_pre_ctr_egress_start4();

	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	return goog_sfc_reset_egress_state();
}

static __always_inline int
pre_ctr_egress_svc4(struct __ctx_buff *ctx,
		    struct goog_ctr_egress_svc4_ctx *stage_ctx)
{
	int ret = geneve_redirect_to_overlay_if_encapped(ctx);

	if (ret != HOOK_ACT_CONTINUE)
		return ret;

	ret = goog_maybe_redirect_if_dhcp(ctx);
	if (ret != HOOK_ACT_CONTINUE)
		return ret;

	ret = goog_maybe_try_pip_egress_redirect4(ctx);
	if (ret != HOOK_ACT_CONTINUE)
		return ret;

	return goog_sfc_maybe_encap_existing(ctx, stage_ctx);
}

static __always_inline int
pre_ctr_egress_pol4(struct __ctx_buff *ctx __maybe_unused,
		    struct goog_ctr_egress_pol4_ctx *stage_ctx __maybe_unused)
{
	return goog_sfc_maybe_skip_egress_policy();
}

static __always_inline int
pre_ctr_egress_fwd4(struct __ctx_buff *ctx,
		    struct goog_ctr_egress_fwd4_ctx *stage_ctx)
{
	int ret = goog_sfc_maybe_encap_new(ctx, stage_ctx);

	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	ret = goog_vpc_pre_ctr_egress_fwd4(ctx, stage_ctx);
	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	ret = google_strict_egress_policy_pre_ctr_egress_fwd4(stage_ctx);
	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	ret = google_perimeter_egress_policy_pre_ctr_egress_fwd4(ctx, stage_ctx);
	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	ret = goog_elb_from_lxc(ctx, stage_ctx);
	if (ret != HOOK_ACT_CONTINUE)
		return ret;

	stage_ctx->skip_local_delivery = should_skip_local_delivery(ctx);
	return HOOK_ACT_CONTINUE;
}
