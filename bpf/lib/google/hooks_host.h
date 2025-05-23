#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "lib/google/plugin.h"

/**
 * This file contains hook implementations for hook points inside the host
 * datapath (bpf_host.c). Put Google code here. #include other Google code as
 * needed.
 *
 * NOTE: CONSULT THE DPV2 CORE TEAM BEFORE MODIFYING EXISTING HOOKS OR ADDING
 * NEW HOOK POINTS.
 */

/**
 * Netdev ingress hooks
 *
 *             |
 * pre_netdev_ingress_start()
 *             |
 *  ___________V___________
 * |                       |
 * |  NETDEV_INGRESS_START | cil_from_netdev
 * |_______________________|
 *            |
 * pre_netdev_ingress_hfw4()
 *            |
 *  __________V____________
 * |                       |
 * |  NETDEV_INGRESS_HFW4  | handle_ipv4_cont
 * |_______________________|
 *            |
 * pre_netdev_ingress_fwd4()
 *            |
 *  __________V____________
 * |                       |
 * |  NETDEV_INGRESS_FWD4  | handle_ipv4_cont
 * |_______________________|
 */
static __always_inline
int pre_netdev_ingress_start(struct __ctx_buff *ctx __maybe_unused,
			     struct goog_netdev_ingress_start_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline
int pre_netdev_ingress_hfw4(struct __ctx_buff *ctx __maybe_unused,
			    struct goog_netdev_ingress_hfw4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline
int pre_netdev_ingress_fwd4(struct __ctx_buff *ctx __maybe_unused,
			    struct goog_netdev_ingress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

/**
 * Host ingress hooks
 *
 *             |
 *  pre_host_ingress_start()
 *             |
 *  ___________V___________
 * |                       |
 * |   HOST_INGRESS_START  | cil_from_host
 * |_______________________|
 *            |
 *  pre_host_ingress_hfw4()
 *            |
 *  __________V____________
 * |                       |
 * |   HOST_INGRESS_HFW4   | handle_ipv4_cont
 * |_______________________|
 *            |
 *  pre_host_ingress_fwd4()
 *            |
 *  __________V____________
 * |                       |
 * |   HOST_INGRESS_FWD4   | handle_ipv4_cont
 * |_______________________|
 */
static __always_inline
int pre_host_ingress_start(struct __ctx_buff *ctx __maybe_unused,
			   struct goog_host_ingress_start_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline
int pre_host_ingress_hfw4(struct __ctx_buff *ctx __maybe_unused,
			  struct goog_host_ingress_hfw4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline
int pre_host_ingress_fwd4(struct __ctx_buff *ctx __maybe_unused,
			  struct goog_host_ingress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}
