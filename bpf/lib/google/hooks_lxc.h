#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "lib/google/sfc.h"
#include "lib/google/plugin.h"

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
 * |                     |
 * |  CTR_INGRESS_POL4   | tail_ipv4_policy
 * |_____________________|
 *            |
 *  __________V__________
 * |                     |
 * |  CTR_INGRESS_DEL4   | tail_ipv4_policy
 * |_____________________|
 */
static __always_inline int
pre_ctr_ingress_ct4(struct __ctx_buff *ctx,
		    struct goog_ctr_ingress_ct4_ctx *stage_ctx)
{
	return goog_sfc_maybe_decap(ctx, stage_ctx);
}

static __always_inline int
pre_ctr_ingress_pol4(struct __ctx_buff *ctx __maybe_unused,
		     struct goog_ctr_ingress_ct4_ctx *stage_ctx __maybe_unused)
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
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
pre_ctr_egress_svc4(struct __ctx_buff *ctx,
		    struct goog_ctr_egress_svc4_ctx *stage_ctx)
{
	return goog_sfc_maybe_encap_existing(ctx, stage_ctx);
}

static __always_inline int
pre_ctr_egress_pol4(struct __ctx_buff *ctx __maybe_unused,
		    struct goog_ctr_egress_pol4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
pre_ctr_egress_fwd4(struct __ctx_buff *ctx __maybe_unused,
		    struct goog_ctr_egress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}
