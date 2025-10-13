#pragma once

#include "common.h"
#include "l4.h"
#include "google_maps.h"
#include "trace.h"
#include "stubs.h"
#include "google_common.h"
#include "lib/eps.h"

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

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

#define V4_ADDR_LEN (sizeof(__u32)*8)  // 32

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

static __always_inline __maybe_unused struct host_dev_routing_entry *
lookup_host_dev_routes4(__u32 ifindex, __be32 addr)
{
	struct host_dev_routing_key key = {
		.lpm_key = { HOST_DEV_ROUTING_STATIC_PREFIX4 + V4_ADDR_LEN, {} },
		.family = ENDPOINT_KEY_IPV4,
		.if_index = ifindex,
		.ip4 = addr,
	};
	return map_lookup_elem(&HOST_DEV_ROUTING_MAP, &key);
}

// fib_redirect_google_multinic will redirect packets by identifying the neighbour to redirect to,
// by looking up the destination IP and ifindex passed in the parameters.
/**
 * @param fib_params - pre-populated fiblookup parameters with IP family and destination IP information.
 * @param ifindex - index of the interface to exit the traffic through.
 * @returns A positive code returned by bpf_redirect* or CTX_ACT_OK next hop cannot be determined	.
 */
static __always_inline int fib_redirect_google_multinic(struct __ctx_buff *ctx __maybe_unused, const struct bpf_fib_lookup_padded *fib_params, int *ifindex, __s8 *ext_err __maybe_unused) {

	struct bpf_redir_neigh nh_params;
	struct host_dev_routing_entry *entry;

	nh_params.nh_family = fib_params->l.family;
	entry = lookup_host_dev_routes4(*ifindex, fib_params->l.ipv4_dst);
	if(entry == NULL) {
		return CTX_ACT_OK;
	}
	// destination is within host subnet, next hop is same as destination IP in fib_params
	if(entry->ip4 == 0) {
		__bpf_memcpy_builtin(&nh_params.ipv6_nh,
					     &fib_params->l.ipv6_dst,
					     sizeof(nh_params.ipv6_nh));
	} else {
		// next hop is gateway IP
		__bpf_memcpy_builtin(&nh_params.ipv6_nh,
					     &entry->ip4,
					     sizeof(nh_params.ipv6_nh));
	}
	if (neigh_resolver_available()) {
	    return redirect_neigh(*ifindex, &nh_params,
	                        sizeof(nh_params), 0);
	}
	return CTX_ACT_OK;
}

static __always_inline int google_fib_do_redirect(struct __ctx_buff *ctx __maybe_unused,
	const struct bpf_fib_lookup_padded __maybe_unused *fib_params,
    __s8 __maybe_unused *fib_ret,
	int __maybe_unused *oif) {

#if defined(IS_BPF_LXC) && defined(MULTI_NIC_DEVICE_TYPE)
#if MULTI_NIC_DEVICE_TYPE != EP_DEV_TYPE_INDEX_MULTI_NIC_VETH
	// L2 + ETP:Local :- For L2 connected LXC, kernel does the routing and sets the L2 addresses
	// accordingly.
	return CTX_ACT_TX;
#else
	int ret;
	// L3 + ETP:Local :- redirect to right parent device which will exit the packet
	// with the hostdevrouting bpf map.
	*oif = PARENT_DEV_IFINDEX;
	ret = fib_redirect_google_multinic(ctx, fib_params, oif, fib_ret);
	if(ret != CTX_ACT_OK) {
		return ret;
	}
#endif
#elif defined(IS_BPF_HOST) && defined(ENABLE_GOOGLE_MULTI_NIC)
	// L2/L3 + ETP:Cluster (LB-Node): reply path of packets on the LB node for ETP:Cluster MN services.
	// redirect reply packets to the interface corresponding to the network using the hostdevrouting bpf map.
	if (DIRECT_ROUTING_DEV_IFINDEX != NATIVE_DEV_IFINDEX) {
		*oif = NATIVE_DEV_IFINDEX;
		return fib_redirect_google_multinic(ctx, fib_params, oif, fib_ret);
	}
#endif /* IS_BPF_HOST && ENABLE_GOOGLE_MULTI_NIC */
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
																	  struct iphdr *ip4 __maybe_unused, bool *should_route_endpoint)
{
	*should_route_endpoint = false;
	return CTX_ACT_OK;
}

#else

/**
 * Redirect packets from host to L3 multinic endpoints if IP is found
 * in local ep map and is intended for the correct native dev index.
 * @arg ctx:      			packet
 * @arg seclabel: 			identity of the source
 * @arg ip4:      			ipv4 header
 * @arg should_to_endpoint: Set to true if the endpoint is a multi-NIC VETH
 * endpoint AND endpoint routes are disabled. Set to false by default.
 *
 * Return CTX_ACT_OK if the packet needs further processing (not redirected).
 *        Or a possitive code returned by bpf_redirect where no futher processing needed.
 *        DROP_UNROUTABLE if packets is intended to be from a different native device.
 */
static __always_inline int try_google_L3_fast_redirect(struct __ctx_buff *ctx, __u32 seclabel,
													   struct iphdr *ip4, bool *should_to_endpoint)
{
	struct endpoint_info *ep;
	const struct multi_nic_dev_info __maybe_unused *dev;
	union macaddr __maybe_unused *dmac;
	// Initialize the output parameter.
	*should_to_endpoint = false;
	/* Lookup IPv4 address in list of local endpoints and host IPs */
	ep = lookup_ip4_endpoint(ip4);
	if (!(ep && ep->flags & ENDPOINT_F_MULTI_NIC_VETH)) {
		// Not a multinic-veth ep, pass through
		return CTX_ACT_OK;
	}

#ifndef ENABLE_ENDPOINT_ROUTES
	*should_to_endpoint = true;
	return CTX_ACT_OK;
#endif /* ENABLE_ENDPOINT_ROUTES */

	dmac = (union macaddr *)&ep->mac;
	dev = lookup_multi_nic_dev(dmac);
	if (dev == NULL || dev->ifindex != NATIVE_DEV_IFINDEX)
	{
		// Recieved traffic intended for a multinic veth endpoint,
		// but packet is sent to the wrong native/parent device. Drop it.
		return DROP_UNROUTABLE;
	}

	return redirect_google_ep(ctx, seclabel, ip4, ep);
}

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
	const union macaddr *smac = (union macaddr *)&eth->h_source;
	const union macaddr host_mac = THIS_INTERFACE_MAC;
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

	// Redirect should only happen between local host and local multinic.
	// Pass through to kernel if the packet is different from
	// the host MAC.
	if (eth_addrcmp(smac, &host_mac)) {
		return CTX_ACT_OK;
	}

#ifdef TUNNEL_MODE
{
	struct endpoint_info *ep;
	struct iphdr *ip4;
	void *data, *data_end;
	struct remote_endpoint_info *info = NULL;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		goto l2_redirect;

	ep = lookup_ip4_endpoint(ip4);

	// Redirect to cilium_host interface if ipcache lookup
	// is successful and tunnel endpoint exists. The traffic
	// is exepcted to get tunneld to the remote host.
	if (!ep) {
		info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		if (info && info->tunnel_endpoint != 0 && !identity_is_remote_node(info->sec_identity)) {
			return redirect(CILIUM_IFINDEX, 0);
		}
	}

	if (!(ep && ep->flags & ENDPOINT_F_MULTI_NIC_VETH)) {
		// Not a multinic-veth ep, pass through to l2 redirect.
		goto l2_redirect;
	}

	dmac = (union macaddr *)&ep->mac;
	dev = lookup_multi_nic_dev(dmac);
	if (dev == NULL || dev->ifindex != NATIVE_DEV_IFINDEX)
	{
		// Recieved traffic intended for a multinic veth endpoint,
		// but packet is sent to the wrong native/parent device. Drop it.
		return DROP_UNROUTABLE;
	}

	goto to_ingress;

}
l2_redirect:
#endif /* TUNNEL_MODE */

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

static __always_inline __maybe_unused bool
should_skip_local_delivery(struct __ctx_buff *ctx __maybe_unused)
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
	__be16 sport;
    if (nexthdr == IPPROTO_UDP) {
		if (l4_load_port(ctx, l4_off + UDP_SPORT_OFF, &sport) < 0)
			return DROP_INVALID;
		if (l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport) < 0)
			return DROP_INVALID;
		if (unlikely(dport == bpf_htons(DHCP_REQUEST_UDP_DPORT))) {
			if (unlikely(sport == bpf_htons(DHCP_REQUEST_UDP_DPORT))) {
				// sport and dport are both equal to 67 when a DHCP server VM is unicast
				// replying to a DHCP request from a DHCP relay server. In those cases,
				// just let packet passthrough. Ref. b/375039839
				return CTX_ACT_OK;
			}
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

static __always_inline __maybe_unused bool
should_skip_local_delivery(struct __ctx_buff *ctx)
{
	struct endpoint_info *ep;
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return false;

	ep = __lookup_ip4_endpoint(ip4->daddr);
	if (!ep)
		return false;
#if MULTI_NIC_DEVICE_TYPE == EP_DEV_TYPE_INDEX_MULTI_NIC_VETH
	{
#  ifndef TUNNEL_MODE
		union macaddr *dmac;
		const struct multi_nic_dev_info *dev;

		dmac = (union macaddr *)&ep->mac;
		dev = lookup_multi_nic_dev(dmac);
		// Temporary solution for VPC peering in GDCH:
		// Remove the network isolation between multi NIC endpoint veth
		// and the default network veth.
		// TUNNEL_MODE and EP_DEV_TYPE_INDEX_MULTI_NIC_VETH macros
		// assume running the datapath in the GDCH environment.
		// The network isolation still applies to multi NIC veth endpoints
		// with different NETWORK_IDs.
		if (dev != NULL && dev->net_id != NETWORK_ID) {
			return true;
		}
#  endif /* !TUNNEL_MODE */
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
