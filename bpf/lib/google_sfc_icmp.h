#pragma once

#include "common.h"
#include "google_sfc.h"

#ifdef ENABLE_GOOGLE_SERVICE_STEERING

 /**
   * Convert the packet into a ICMP fragmentation needed packet and redirect it.
   *
   * @arg ctx: Packet
   * @arg ip4: Pointer to L3 header
   * @arg rev_nat_index: Used to find the original LB service the packet is sent to.
   *
   * Return negative `DROP_` codes if the packet can't be handled.
   * Return `CTX_ACT_REDIRECT` if the ICMP packet is succesfully built and redirected.
   */
static __always_inline int
sfc_redirect_icmp4(struct __ctx_buff *ctx, struct iphdr *ip4, __u16 rev_nat_index) {
	int ret;
	__u32 redirect_dir = 0;
	__u32 svc_addr = 0;
	__u16 dport = 0;
	// rev_nat_index is set if the packet has been service load balanced.
	// Need to do reverse DNAT in the innner headers when building the ICMP pkt.
	if (rev_nat_index) {
		const struct lb4_reverse_nat *nat =
		    map_lookup_elem(&LB4_REVERSE_NAT_MAP, &rev_nat_index);
		if (nat == NULL) {
			return DROP_NO_SERVICE;
		}
		svc_addr = nat->address;
		dport = nat->port;
	}
	ret = __sfc_reply_icmp4(ctx, ip4, svc_addr, dport);
	if (IS_ERR(ret))
		return ret;
	return ctx_redirect(ctx, ctx_get_ifindex(ctx), redirect_dir);
}

#endif /* ENABLE_GOOGLE_SERVICE_STEERING */