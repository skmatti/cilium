#pragma once

#if defined(IS_BPF_HOST) || defined(IS_BPF_LXC)

#include "common.h"
#include "l3.h"

// redirect_google_ep is a wrapper around ipv4_local_delivery to preset some
// input arguments
static __always_inline int redirect_google_ep(
	struct __ctx_buff *ctx, __u32 seclabel, struct iphdr *ip4,
	const struct endpoint_info *ep)
{
	return ipv4_local_delivery(
		ctx, ETH_HLEN, seclabel, MARK_MAGIC_IDENTITY, ip4, ep,
		METRIC_INGRESS, false, false, 0);
}

#endif