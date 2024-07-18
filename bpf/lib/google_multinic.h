#ifndef __LIB_GOOGLE_MULTINIC_H_
#define __LIB_GOOGLE_MULTINIC_H_

#include "common.h"
#include "l4.h"
#include "google_maps.h"

DEFINE_U32(POD_STACK_REDIRECT_IFINDEX, 0xdeadbeef);
#define POD_STACK_REDIRECT_IFINDEX fetch_u32(POD_STACK_REDIRECT_IFINDEX)

// Should only be used for Multi NIC endpoints.
DEFINE_U16(MULTI_NIC_ENDPOINT_MTU, 0x270f);
#define MULTI_NIC_ENDPOINT_MTU fetch_u16(MULTI_NIC_ENDPOINT_MTU)

#ifndef NODEPORT_IPV4_BY_IFINDEX
#define NODEPORT_IPV4_BY_IFINDEX(IFINDEX) ({ int __tmp __maybe_unused = IFINDEX; 0; })
#endif

DEFINE_U32(PARENT_DEV_IFINDEX, 0xdeadbeef);
#define PARENT_DEV_IFINDEX fetch_u32(PARENT_DEV_IFINDEX)

DEFINE_U32(NETWORK_ID, 0xdeadbeef);
#define NETWORK_ID fetch_u32(NETWORK_ID)

DEFINE_MAC(PARENT_DEV_MAC, 0xde, 0xad, 0xbe, 0xef, 0xc0, 0xde);
#define PARENT_DEV_MAC fetch_mac(PARENT_DEV_MAC)

#define DHCP_REQUEST_UDP_DPORT   67
#define DHCP_RESPONSE_UDP_DPORT  68

// Corresponding values to the multinic device types.
// Note this should match the go equivalant in device_type.go
#define EP_DEV_TYPE_INDEX_VETH 0
#define EP_DEV_TYPE_INDEX_MULTI_NIC_VETH 1
#define EP_DEV_TYPE_INDEX_MACVTAP 2
#define EP_DEV_TYPE_INDEX_MACVLAN 3
#define EP_DEV_TYPE_INDEX_IPVLAN 4

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
 * For testing veth multinic:
 *   MAX_BASE_OPTIONS="-DENABLE_GOOGLE_MULTI_NIC=1 -DNATIVE_DEV_IFINDEX=0 -DMULTI_NIC_DEVICE_TYPE=1" make bpf
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

static __always_inline __maybe_unused int try_google_L3_fast_redirect(struct __ctx_buff *ctx __maybe_unused,
																	  __u32 seclabel __maybe_unused,
																	  struct iphdr *ip4 __maybe_unused)
{
	return CTX_ACT_OK;
}

#else

/** A trimmed version of ipv4_local_delivery that forces bpf_redirect. */
static __always_inline int __redirect_multinic_ep(struct __ctx_buff *ctx, int l3_off,
					       __u32 seclabel, struct iphdr *ip4,
					       const struct endpoint_info *ep)
{
	mac_t router_mac = ep->node_mac;
	mac_t lxc_mac = ep->mac;
	int ret;


	ret = ipv4_l3(ctx, l3_off, (__u8 *) &router_mac, (__u8 *) &lxc_mac, ip4);
	if (ret != CTX_ACT_OK)
		return ret;

	ctx->mark |= MARK_MAGIC_IDENTITY;
	set_identity_mark(ctx, seclabel);
	return redirect_ep(ctx, ep->ifindex, false);
}

/**
 * Redirect packets from host to L3 multinic endpoints if IP is found
 * in local ep map and is intended for the correct native dev index.
 * @arg ctx:      packet
 * @arg seclabel: identity of the source
 * @arg ip4:      ipv4 header
 *
 * Return CTX_ACT_OK if the packet needs further processing (not redirected).
 *        Or a possitive code returned by bpf_redirect where no futher processing needed.
 *        DROP_UNROUTABLE if packets is intended to be from a different native device.
 */
static __always_inline int try_google_L3_fast_redirect(struct __ctx_buff *ctx, __u32 seclabel,
													   struct iphdr *ip4)
{
	struct endpoint_info *ep;
	const struct multi_nic_dev_info __maybe_unused *dev;
	union macaddr __maybe_unused *dmac;
	/* Lookup IPv4 address in list of local endpoints and host IPs */
	ep = lookup_ip4_endpoint(ip4);
	if (!(ep && ep->flags & ENDPOINT_F_MULTI_NIC_VETH)) {
		// Not a multinic-veth ep, pass through
		return CTX_ACT_OK;
	}

	dmac = (union macaddr *)&ep->mac;
	dev = lookup_multi_nic_dev(dmac);
	if (dev == NULL || dev->ifindex != NATIVE_DEV_IFINDEX)
	{
		// Recieved traffic intended for a multinic veth endpoint,
		// but packet is sent to the wrong native/parent device. Drop it.
		return DROP_UNROUTABLE;
	}

	return __redirect_multinic_ep(ctx, ETH_HLEN, seclabel, ip4, ep);
}

static int BPF_FUNC(clone_redirect, struct __sk_buff *skb, int ifindex,
		    __u32 flags);

static __always_inline void
ctx_google_local_redirect_set(struct __sk_buff *ctx)
{
	ctx->tc_index |= TC_INDEX_F_GOOGLE_LOCAL_REDIRECT;
}

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

#ifndef ENABLE_GOOGLE_MULTI_NIC_HAIRPIN
    return CTX_ACT_OK;
#endif

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
	ctx_google_local_redirect_set(ctx);
	return redirect(NATIVE_DEV_IFINDEX, BPF_F_INGRESS);
}
#endif

#if __ctx_is != __ctx_skb ||  !defined(ENABLE_GOOGLE_MULTI_NIC)
static __always_inline __maybe_unused int redirect_if_dhcp(struct __ctx_buff *ctx __maybe_unused,
                        __u8 nexthdr __maybe_unused, int l4_off __maybe_unused, __be32 saddr __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline __maybe_unused void skip_policy_if_dhcp(struct __ctx_buff *ctx __maybe_unused,
                        __u8 nexthdr __maybe_unused, int l4_off __maybe_unused)
{
	return;
}

static __always_inline __maybe_unused bool ctx_google_local_redirect(struct __ctx_buff *ctx __maybe_unused)
{
	return false;
}

static __always_inline __maybe_unused bool should_skip_local_delivery(const struct endpoint_info *ep __maybe_unused)
{
	return false;
}

#else

static __always_inline bool ctx_google_local_redirect(struct __ctx_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;

	ctx->tc_index &= ~TC_INDEX_F_GOOGLE_LOCAL_REDIRECT;
	return tc_index & TC_INDEX_F_GOOGLE_LOCAL_REDIRECT;
}

static __always_inline void
ctx_skip_google_dhcp_set(struct __sk_buff *ctx)
{
	ctx->tc_index |= TC_INDEX_F_SKIP_POLICY_GOOGLE_DHCP;
}

static __always_inline bool ctx_skip_google_dhcp(struct __sk_buff *ctx)
{
	volatile __u32 tc_index = ctx->tc_index;

	ctx->tc_index &= ~TC_INDEX_F_SKIP_POLICY_GOOGLE_DHCP;
	return tc_index & TC_INDEX_F_SKIP_POLICY_GOOGLE_DHCP;
}

// 0x0050fea9 is the network used by kubevirt for their dummy dhcp server IP address.
// https://gke-internal.googlesource.com/third_party/kubevirt/kubevirt/+/refs/heads/dev/pkg/network/link/address_google.go#9
static __always_inline bool is_kubevirt_dhcp(__be32 saddr) {
	return ((saddr&0x00ffffff) == 0x0050fea9);
}

/**
 * Redirect dhcp client packets
 * if destination port is 67 on UDP(dhcp-request), redirect to pod-network interface
 * to be further sent to container for dhcp-server processing.
 * if destination port is 68 on UDP(dhcp-response), set TC_INDEX_F_SKIP_POLICY_GOOGLE_DHCP then
 * hairpin the packet from egress to ingress direction on the same inteface on which
 * the packet is seen by this program.
 * @arg ctx:      packet
 * @arg nexthdr:  l3 next header field
 * @arg l4_off:   offset to L4 header
 *
 * Return CTX_ACT_OK if the packet needs further processing.
 *        Or a positive code returned by bpf_redirect where no further processing needed.
 *        A negative DROP_* code on error.
 */
static __always_inline __maybe_unused int redirect_if_dhcp(struct __ctx_buff *ctx,
                        __u8 nexthdr, int l4_off, __be32 saddr)
{
    __be16 dport;
    if (nexthdr == IPPROTO_UDP) {
        if (l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport) < 0)
            return DROP_INVALID;
        if (unlikely(dport == bpf_htons(DHCP_REQUEST_UDP_DPORT))) {
            // Redirect to an interface that will release the packet to the pod-namespace stack
            send_trace_notify(ctx, TRACE_TO_STACK, 0, 0,
                              0, ctx->ifindex,
                              REASON_GOOGLE_DHCP_REQ_REDIRECT, TRACE_PAYLOAD_LEN);
            return redirect(POD_STACK_REDIRECT_IFINDEX, BPF_F_INGRESS);
        } else if (unlikely((dport == bpf_htons(DHCP_RESPONSE_UDP_DPORT)) && is_kubevirt_dhcp(saddr))) {
            // DHCP clients don't care if the source mac address is a broadcast mac.
            const __u8 dhcp_source_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } ;

            // Redirect, to hairpin back on the same interface
            send_trace_notify(ctx, TRACE_TO_STACK, 0, 0, 0,
                              ctx->ifindex,
                              REASON_GOOGLE_DHCP_RESP_REDIRECT, TRACE_PAYLOAD_LEN);
            // DHCP response packets hairpin back on the same interface are self-generated
            // from the endpoint and should not have policy enforcement after redirect.
            // Set TC_INDEX_F_SKIP_POLICY_GOOGLE_DHCP before haripin.
            // The tc_index value is extracted on the INGRESS of the same interface and
            // constructs the program to skip policy enforcement.
            ctx_skip_google_dhcp_set(ctx);

            // Due to b/232956565, Windows VMs don't take DHCP responses
            // if the source mac address is the same as its interface.
            // Modify the source mac address of DHCP responses to
            // the broadcast mac here before redirect.
            if (eth_store_saddr(ctx, dhcp_source_mac, 0) < 0) {
		        return DROP_WRITE_ERROR;
            }
            return redirect(ctx->ifindex, BPF_F_INGRESS);
        }

    }
    return CTX_ACT_OK;
}

/**
 * Skip policy enforcement for DHCP packets hairpin back from redirect_if_dhcp()
 * @arg ctx:      packet
 * @arg nexthdr:  l3 next header field
 * @arg l4_off:   offset to L4 header
 *
 * Directly return if TC_INDEX_F_SKIP_POLICY_GOOGLE_DHCP is not set.
 * Otherwise set CB_POLICY to skip policy enforcement for DHCP response packets.
 */
static __always_inline __maybe_unused void skip_policy_if_dhcp(struct __ctx_buff *ctx,
                       __u8 nexthdr, int l4_off)
{
    __be16 dport __maybe_unused;
    if (unlikely(ctx_skip_google_dhcp(ctx))) {
        if (nexthdr == IPPROTO_UDP) {
            if (l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport) < 0)
                return;
            if (dport == bpf_htons(DHCP_RESPONSE_UDP_DPORT)) {
                ctx_store_meta(ctx, CB_POLICY, 1);
                return;
            }
        }
    }
    return;
}

static __always_inline __maybe_unused bool should_skip_local_delivery(const struct endpoint_info *ep __maybe_unused)
{
#if MULTI_NIC_DEVICE_TYPE == EP_DEV_TYPE_INDEX_MULTI_NIC_VETH
{
	union macaddr *dmac;
	const struct multi_nic_dev_info *dev;

	dmac = (union macaddr *)&ep->mac;
	dev = lookup_multi_nic_dev(dmac);
#ifdef TUNNEL_MODE
	// Temporary solution for VPC peering in GDCH:
	// Remove the network isolation between multi NIC endpoint veth
	// and the default network veth.
	// TUNNEL_MODE and EP_DEV_TYPE_INDEX_MULTI_NIC_VETH macros
	// assume running the datapath in the GDCH environment.
	// The network isolation still applies to multi NIC veth endpoints
	// with different NETWORK_IDs.
	if (dev != NULL && dev->net_id != NETWORK_ID)
	{
		return true;
	}
#else
	// If the destination endpoint is a multi NIC endpoint veth pair,
	// we want local delivery to be done only between endpoints that
	// share the same NETWORK_ID.
	if (dev == NULL || dev->net_id != NETWORK_ID)
	{
		return true;
	}
#endif /* TUNNEL_MODE */
	return false;
}
#endif /* MULTI_NIC_DEVICE_TYPE == EP_DEV_TYPE_INDEX_MULTI_NIC_VETH */
	// Temporary solution for VPC peering in GDCH:
	// If the source endpoint is not a multinic veth endpoint,
	// we always enable local delivery if TUNNEL_MODE is defined.
#ifndef TUNNEL_MODE
	// Skip local delivery if src is a default network veth and dst is
	// a multinic-veth. This helps enforce isolation between default
	// network and multinic L3 networks.
	// This section is only excercised by default (L3) network when
	// ENABLE_ROUTING is true. L2 multinic endpoints does not reach here
	// because it doesn't have ENABLE_ROUTING.
	if (ep->flags & ENDPOINT_F_MULTI_NIC_VETH)
	{
		return true;
	}
#endif /* TUNNEL_MODE */
	return false;
}

#endif

#endif /* __LIB_GOOGLE_MULTINIC_H_ */
