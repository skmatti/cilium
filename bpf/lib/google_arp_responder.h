#ifndef __LIB_GOOGLE_ARP_RESPONDER_H_
#define __LIB_GOOGLE_ARP_RESPONDER_H_

#include "arp.h"
#include "eps.h"

static __always_inline int
handle_google_arp(struct __ctx_buff *ctx __maybe_unused, const bool from_host __maybe_unused)
{
#if !defined(TUNNEL_MODE) && defined(ENABLE_FLAT_IPV4)
   if (!from_host) {
      union macaddr mac = NODE_MAC;
      __be32 sip;
      __be32 tip;
      union macaddr smac;
      struct endpoint_info *ep;

      if (arp_validate(ctx, &mac, &smac, &sip, &tip)) {
        /* Lookup if tip address is in list of local endpoints and host IPs */
        ep = __lookup_ip4_endpoint(tip);
        /* Exclude Host and MultiNIC endpoints */
        if (ep && !(ep->flags & ENDPOINT_F_HOST) && !(ep->flags & ENDPOINT_F_MULTI_NIC)) {
          return arp_respond(ctx, &mac, tip, &smac, sip, 0);
        }
      }
   }
#endif /* !TUNNEL_MODE && ENABLE_FLAT_IPV4 */
  return CTX_ACT_OK;
}

#endif /* __LIB_GOOGLE_ARP_RESPONDER_H_ */