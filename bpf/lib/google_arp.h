#pragma once
// #ifndef __LIB_GOOGLE_ARP_H_
// #define __LIB_GOOGLE_ARP_H_

#include "arp.h"
#include "eps.h"

#ifndef LXC_MAC
DEFINE_MAC(LXC_MAC, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
#define LXC_MAC fetch_mac(LXC_MAC)
#endif

static __always_inline int
handle_google_arp(struct __ctx_buff *ctx __maybe_unused, const bool from_host __maybe_unused)
{
#if !defined(TUNNEL_MODE) && defined(ENABLE_FLAT_IPV4)
   if (!from_host) {
      union macaddr mac = THIS_INTERFACE_MAC;
      __be32 sip;
      __be32 tip;
      union macaddr smac;
      struct endpoint_info *ep;

      if (arp_validate(ctx, &mac, &smac, &sip, &tip)) {
        /* Lookup if tip address is in list of local endpoints and host IPs */
        ep = __lookup_ip4_endpoint(tip);
        /* Exclude Host and MultiNIC endpoints */
        if (ep && !(ep->flags & ENDPOINT_F_HOST) && !(ep->flags & ENDPOINT_F_MULTI_NIC_L2)) {
          return arp_respond(ctx, &mac, tip, &smac, sip, 0);
        }
      }
   }
#endif /* !TUNNEL_MODE && ENABLE_FLAT_IPV4 */
  return CTX_ACT_OK;
}

#ifndef IS_BPF_HOST
static __always_inline
int is_valid_lxc_src_mac(struct __ctx_buff *ctx, __u8 nexthdr __maybe_unused)
{
	union macaddr lxc_mac = LXC_MAC;
	struct ethhdr *eth;
	void *data = ctx_data(ctx);
	void *data_end = ctx_data_end(ctx);
	union macaddr *smac = NULL, *dmac __maybe_unused = NULL;

	// early return if the ethernet header doesn't exist in the packet.
	if (data + sizeof(struct ethhdr) > data_end)
		return true;

	eth = data;
	*smac = *(union macaddr *) &eth->h_source;
	if (!eth_addrcmp(smac, &lxc_mac))
		return true;

// ICMP reject packet uses reversed ethernet header in __tail_no_service_ipv4,
// we need to validate dmac to cover this case.
#ifdef SERVICE_NO_BACKEND_RESPONSE
	if (nexthdr != IPPROTO_ICMP) {
		dmac = (union macaddr *) &eth->h_source;
		return !eth_addrcmp(smac, &lxc_mac);
	}
#endif

	return false;
}

static __always_inline int arp_validate_mac_spoof(const struct __ctx_buff *ctx)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	struct arphdr *arp = data + ETH_HLEN;
	struct ethhdr *eth = data;
	union macaddr smac, lxc_mac = LXC_MAC;
	struct arp_eth *arp_eth;

	if (data + ETH_HLEN > data_end)
		return CTX_ACT_OK;

	smac = *(union macaddr *) &eth->h_source;
	if (eth_addrcmp(&lxc_mac, &smac))
		return DROP_GOOGLE_INVALID_SMAC;

	// Pass unknown packets to kernel.
	if (data + ETH_HLEN + sizeof(*arp) + sizeof(*arp_eth) > data_end)
		return CTX_ACT_OK;

	arp_eth = data + ETH_HLEN + sizeof(*arp);
	// Validate the ARP reply's sender hardware address
	// against LXC MAC. If DISABLE_SIP_VERIFICATION isn't
	// present, also validate the sender's IP against
	// LXC IP.
	if (arp->ar_op == bpf_htons(ARPOP_REPLY) &&
		arp->ar_hrd == bpf_htons(ARPHRD_ETHER) &&
		((memcmp(arp_eth->ar_sha, lxc_mac.addr, ETH_ALEN) != 0)
#ifndef DISABLE_SIP_VERIFICATION
		|| arp_eth->ar_sip != LXC_IPV4
#endif /* DISABLE_SIP_VERIFICATION */
		)) {
			return DROP_GOOGLE_INVALID_SMAC;
	}

	return CTX_ACT_OK;
}
#endif /* IS_BPF_HOST */
// #endif /* __LIB_GOOGLE_ARP_H_ */
