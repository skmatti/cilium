#pragma once

#if defined(IS_BPF_HOST) || defined(IS_BPF_LXC)

#include "common.h"
#include "l3.h"

/** A trimmed version of ipv4_local_delivery that forces bpf_redirect. */
static __always_inline int __redirect_google_ep(struct __ctx_buff *ctx, int l3_off,
					       __u32 seclabel, struct iphdr *ip4,
					       const struct endpoint_info *ep, bool from_tunnel)
{
	mac_t router_mac = ep->node_mac;
	mac_t lxc_mac = ep->mac;
	int ret;

	ret = ipv4_l3(ctx, l3_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac, ip4);
	if (ret != CTX_ACT_OK)
		return ret;

	set_identity_mark(ctx, seclabel, MARK_MAGIC_IDENTITY);
	return redirect_ep(ctx, ep->ifindex, false, from_tunnel);
}

#endif