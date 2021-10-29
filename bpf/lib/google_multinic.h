#ifndef __LIB_GOOGLE_MULTINIC_H_
#define __LIB_GOOGLE_MULTINIC_H_

#include "common.h"
#include "l4.h"
#include "google_maps.h"

DEFINE_U32(POD_STACK_REDIRECT_IFINDEX, 0xdeadbeef);
#define POD_STACK_REDIRECT_IFINDEX fetch_u32(POD_STACK_REDIRECT_IFINDEX)


#define DHCP_REQUEST_UDP_DPORT   67
#define DHCP_RESPONSE_UDP_DPORT  68

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


/* To test compilation with ENABLE_GOOGLE_MULTI_NIC:
 *   MAX_BASE_OPTIONS="-DENABLE_GOOGLE_MULTI_NIC=1 -DNATIVE_DEV_IFINDEX=0" make bpf
 */

// multinic_redirect_ipv4 is only needed on host devices with tc filters.
// We require skb because we only defines BPF_FUNC for skb.
#if __ctx_is != __ctx_skb || !defined(IS_BPF_HOST) ||                          \
    !defined(ENABLE_GOOGLE_MULTI_NIC)
static __always_inline __maybe_unused int
multinic_redirect_ipv4(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}
#else

static int BPF_FUNC(clone_redirect, struct __sk_buff *skb, int ifindex,
		    __u32 flags);

/**
 * Redirect ipv4 multinic traffic back to local kernel if needed.
 * L2 broadcast traffic is cloned and redirected too.
 * @arg ctx:      packet
 *
 * Return CTX_ACT_OK if the packet needs further processing.
 *        Or a possitive code returned by bpf_redirect where no futher processing needed.
 *        A negative DROP_* code on error.
 */
static __always_inline __maybe_unused int
multinic_redirect_ipv4(struct __ctx_buff *ctx)
{
	struct ethhdr *eth = ctx_data(ctx);
	const union macaddr *dmac = (union macaddr *)&eth->h_dest;
	const union macaddr host_mac = NODE_MAC;
	__u16 proto = 0;
	const struct multi_nic_dev_info *dev;

	if (!validate_ethertype(ctx, &proto)) {
		return DROP_UNSUPPORTED_L2;
	}

	// If dmac is L2 broadcast, sends the copied packet back.
	if (eth_is_bcast(dmac)) {
		int ret =
		    clone_redirect(ctx, NATIVE_DEV_IFINDEX, BPF_F_INGRESS);
		if (ret != 0) {
			return DROP_INVALID;
		}
		return CTX_ACT_OK;
	}

	if (!eth_addrcmp(dmac, &host_mac)) {
		goto to_ingress;
	}

	dev = lookup_multi_nic_dev(dmac);
	if (dev != NULL && dev->ifindex == NATIVE_DEV_IFINDEX) {
		goto to_ingress;
	}

	return CTX_ACT_OK;

to_ingress:
	send_trace_notify(ctx, TRACE_TO_STACK, 0, 0, 0, NATIVE_DEV_IFINDEX, 0,
			  0);
	return redirect(NATIVE_DEV_IFINDEX, BPF_F_INGRESS);
}
#endif

#if __ctx_is != __ctx_skb ||  !defined(ENABLE_GOOGLE_MULTI_NIC)
static __always_inline __maybe_unused int redirect_if_dhcp(struct __ctx_buff *ctx __maybe_unused,
                        __u8 nexthdr __maybe_unused, int l4_off __maybe_unused)
{
	return CTX_ACT_OK;
}

#else

/**
 * Redirect dhcp client packets
 * if destination port is 67 on UDP(dhcp-request), redirect to pod-network interface
 * to be further sent to container for dhcp-server processing. if destination port is
 * 68 on UDP(dhcp-response), hairpin the packet from egress to ingress direction
 * on the same inteface on which the packet is seen by this program.
 * @arg ctx:      packet
 * @arg nexthdr:  l3 next header field
 * @arg l4_off:   offset to L4 header
 *
 * Return CTX_ACT_OK if the packet needs further processing.
 *        Or a possitive code returned by bpf_redirect where no futher processing needed.
 *        A negative DROP_* code on error.
 */
static __always_inline __maybe_unused int redirect_if_dhcp(struct __ctx_buff *ctx,
                        __u8 nexthdr, int l4_off)
{
    __be16 dport;
    if (nexthdr == IPPROTO_UDP) {
        if (l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport) < 0)
            return DROP_INVALID;
        if (unlikely(dport == bpf_htons(DHCP_REQUEST_UDP_DPORT))) {
            // Redirect to an interface that will release the packet to the pod-namespace stack
            send_trace_notify(ctx, TRACE_TO_STACK, 0, POD_STACK_REDIRECT_IFINDEX,
                              0, ctx->ifindex,
                              REASON_GOOGLE_DHCP_REQ_REDIRECT, TRACE_PAYLOAD_LEN);
            return redirect(POD_STACK_REDIRECT_IFINDEX, BPF_F_INGRESS);
        } else if (unlikely(dport == bpf_htons(DHCP_RESPONSE_UDP_DPORT))) {
            // Redirect, to hairpin back on the same interface
            send_trace_notify(ctx, TRACE_TO_STACK, 0, 0, 0,
                              ctx->ifindex,
                              REASON_GOOGLE_DHCP_RESP_REDIRECT, TRACE_PAYLOAD_LEN);

            return redirect(ctx->ifindex, BPF_F_INGRESS);
        }

    }
    return CTX_ACT_OK;
}
#endif

#endif /* __LIB_GOOGLE_MULTINIC_H_ */
