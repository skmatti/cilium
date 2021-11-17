#ifndef __LIB_GOOGLE_MULTINIC_H_
#define __LIB_GOOGLE_MULTINIC_H_

#include "common.h"
#include "l4.h"

/**
 * Drop dhcp client packets whose destination port is 67 on UDP.
 * @arg ctx:      packet
 * @arg nexthdr:  l3 next header field
 * @arg l4_off:   offset to L4 header
 *
 * Return CTX_ACT_OK on success or a negative DROP_* reason
 */
static __always_inline __maybe_unused int drop_if_dhcp(struct __ctx_buff *ctx,
                        __u8 nexthdr, int l4_off)
{
    __be16 dport;
    if (nexthdr == IPPROTO_UDP) {
        if (l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport) < 0)
            return DROP_INVALID;
        if (unlikely(dport == bpf_htons(67))) {
            return DROP_HOST_UNREACHABLE;
        }
    }
    return CTX_ACT_OK;
}
#endif /* __LIB_GOOGLE_MULTINIC_H_ */