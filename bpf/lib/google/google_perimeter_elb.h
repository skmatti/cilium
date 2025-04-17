#pragma once

#include "lib/google/hooks_common.h"

/*
 * Google Perimeter ELB Hook Entry Points
 *
 * Both theses bpf_lxc goog_elb_from_lxc and bpf_host goog_elb_from_netdev handle
 * a forward path case and reverse path case internally.
 *
 * For a break down of all Google Perimeter ELB Flags and where they are enabled
 * see https://screenshot.googleplex.com/84UnysX6j4CfQmX
 *
 */
#ifdef ENABLE_EGRESS_GATEWAY_REDIRECT

#include "lib/google_perimeter_elb.h"

static __always_inline
int goog_elb_from_netdev(struct __ctx_buff *ctx,
			 struct goog_host_ingress_fwd4_ctx_common *stage_ctx_common)
{
	return google_perimeter__handle_perimeter_endpoint_host(ctx, stage_ctx_common);
}

static __always_inline
int goog_elb_from_lxc(struct __ctx_buff *ctx, struct goog_ctr_egress_fwd4_ctx *stage_ctx)
{
	return google_perimeter__handle_perimeter_endpoint_lxc(ctx, stage_ctx);
}

#else

static __always_inline
int goog_elb_from_netdev(struct __ctx_buff *ctx __maybe_unused,
			 struct goog_host_ingress_fwd4_ctx_common *stage_ctx_common __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline
int goog_elb_from_lxc(struct __ctx_buff *ctx __maybe_unused,
		      struct goog_ctr_egress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif /* ENABLE_EGRESS_GATEWAY_REDIRECT */
