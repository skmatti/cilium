
#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "lib/common.h"

/**
 * Special return codes used by the Google hook framework. Hooks can return
 * one of these instead of a DROP_* or CTX_ACT_* code to influence control flow.
 *
 * HOOK_ACT_CONTINUE
 *   Don't do anything special after the hook returns. Just execute the stage.
 * HOOK_ACT_SKIP
 *   Skip this stage. Use this, for example, to skip policy enforcement. This
 *   is currently only supported for the CTR_EGRESS_POL4 stage.
 *
 * If adding new special return codes for hooks, make sure their values don't
 * conflict with those defined in bpf/lib/common.h.
 */
#define HOOK_ACT_SKIP -2
#define HOOK_ACT_CONTINUE -3

/**
 * See go/datapath-plugins for discussion around stages.
 */
enum goog_ctr_stage {
	CTR_EGRESS_START,
	CTR_EGRESS_START4,
	CTR_EGRESS_SVC4,
	CTR_EGRESS_POL4,
	CTR_EGRESS_FWD4,
	CTR_INGRESS_START,
	CTR_INGRESS_CT4,
	CTR_INGRESS_POL4,
	CTR_INGRESS_DEL4,

	NETDEV_INGRESS_START,
	NETDEV_INGRESS_HFW4,
	NETDEV_INGRESS_FWD4,
	HOST_INGRESS_START,
	HOST_INGRESS_HFW4,
	HOST_INGRESS_FWD4,
};

/**
 * Stage context definitions
 *
 * Each pre_* hook receives both the TC hook context (struct __ctx_buff *) and
 * a pointer to its "stage context". The stage context passes context about the
 * current execution to the pre_* hook for that stage but hooks can also modify
 * fields in the stage context to influence stage behavior in various ways.
 *
 * NOTE: CONSULT THE DPV2 CORE TEAM BEFORE MODIFYING THESE DEFINITONS.
 */
struct goog_ctr_egress_start4_ctx {
};

struct goog_ctr_egress_svc4_ctx {
	/* Disables source IP validation if set to true. */
	bool disable_sip_validation;
	/* Override the source IP used for service backend selection  */
	__be32 sip_override;
};

struct goog_ctr_egress_pol4_ctx {
};

struct goog_ctr_egress_fwd4_ctx {
	 /* TODO(jrife): Maybe something more generic like CT state makes sense
	  * here. rev_nat_index is pretty tailored towards service steering's code.
	  */
	__u16 rev_nat_index;
	/* Skip local delivery if set to true. */
	bool skip_local_delivery;
};

struct goog_ctr_ingress_ct4_ctx {
	/* True if this is being executed from cil_to_container (when using
	 * endpoint routes) and false if being executed from this endpoint's
	 * handle_policy() program (BPF host routing + no endpoint routes).
	 *
 	 * internal use / read only */
	bool __cil_to_container;
};

struct goog_ctr_ingress_pol4_ctx {
};

struct goog_ctr_ingress_del4_ctx {
};

union goog_ctr_stage_hook_ctx {
	struct goog_ctr_egress_start4_ctx goog_ctr_egress_start4_ctx;
	struct goog_ctr_egress_svc4_ctx goog_ctr_egress_svc4_ctx;
	struct goog_ctr_egress_pol4_ctx goog_ctr_egress_pol4_ctx;
	struct goog_ctr_egress_fwd4_ctx goog_ctr_egress_fwd4_ctx;
	struct goog_ctr_ingress_ct4_ctx goog_ctr_ingress_ct4_ctx;
	struct goog_ctr_ingress_pol4_ctx goog_ctr_ingress_pol4_ctx;
	struct goog_ctr_ingress_del4_ctx goog_ctr_ingress_del4_ctx;
};

struct goog_ctr_stage_ctx {
	union goog_ctr_stage_hook_ctx stage_ctx;
	struct __ctx_buff *ctx;
	enum goog_ctr_stage curr;
	__s8 *ext_err;
};

static __always_inline void
goog_ctr_init_ctx(struct goog_ctr_stage_ctx *stage_ctx)
{
	memset(stage_ctx, 0, sizeof(struct goog_ctr_stage_ctx));
}

struct goog_host_ingress_fwd4_ctx_common {
	__u32 secctx;
};

struct goog_netdev_ingress_start_ctx {
};

struct goog_netdev_ingress_hfw4_ctx {
};

struct goog_netdev_ingress_fwd4_ctx {
	struct goog_host_ingress_fwd4_ctx_common __common;
};

struct goog_host_ingress_start_ctx {
};

struct goog_host_ingress_hfw4_ctx {
};

struct goog_host_ingress_fwd4_ctx {
	struct goog_host_ingress_fwd4_ctx_common __common;
};

union goog_host_stage_hook_ctx {
	struct goog_netdev_ingress_start_ctx goog_netdev_ingress_start_ctx;
	struct goog_netdev_ingress_hfw4_ctx goog_netdev_ingress_hfw4_ctx;
	struct goog_netdev_ingress_fwd4_ctx goog_netdev_ingress_fwd4_ctx;
	struct goog_host_ingress_start_ctx goog_host_ingress_start_ctx;
	struct goog_host_ingress_hfw4_ctx goog_host_ingress_hfw4_ctx;
	struct goog_host_ingress_fwd4_ctx goog_host_ingress_fwd4_ctx;
};

struct goog_host_stage_ctx {
	union goog_host_stage_hook_ctx stage_ctx;
	struct __ctx_buff *ctx;
	enum goog_ctr_stage curr;
	__s8 *ext_err;
};

static __always_inline void
goog_host_init_ctx(struct goog_host_stage_ctx *stage_ctx)
{
	memset(stage_ctx, 0, sizeof(struct goog_host_stage_ctx));
}

/**
 * Define a Google hook point.
 *
 * This macro sets up the stage context, invokes the specified hook function,
 * and returns its return value to the caller.
 *
 * @cx: the SKB context (struct __ctx_buff *).
 * @type: the stage type matching the stage context and hook function suffix (
 * e.g. ctr_egress_start4).
 * @stage: the stage as defined in the hook stage enum (e.g. enum ctr_stage).
 * @sc: the outer stage context struct (e.g. struct ctr_stage_ctx).
 * @exr: a pointer to ext_err in the current context.
 */
#define GOOGLE_HOOK(cx, type, stage, sc, exr)                \
({                                                           \
	int r;                                               \
	sc.ctx = cx;                                         \
	sc.curr = stage;                                     \
	sc.ext_err = exr;                                    \
	r = pre_##type(cx, &sc.stage_ctx.goog_##type##_ctx); \
	r;                                                   \
})
