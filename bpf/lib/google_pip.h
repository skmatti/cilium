#pragma once

#include "google_maps.h"
#include "google_common.h"

#ifdef ENABLE_GOOGLE_PERSISTENT_IP

/* PIP_ROUTING_STATIC_PREFIX gets sizeof non-IP, non-prefix part of pip_cidr_key */
#define PIP_ROUTING_STATIC_PREFIX							\
	(8 * (sizeof(struct pip_cidr_key) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(union v6addr)))

#define V4_ADDR_LEN (sizeof(__u32)*8)  // 32

static __always_inline struct pip_routing_entry *
__pip_routing_lookup4(__be32 addr)
{
	struct pip_cidr_key key = {
		.lpm_key = { PIP_ROUTING_STATIC_PREFIX + V4_ADDR_LEN, {} },
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = addr,
	};
	return map_lookup_elem(&PIP_ROUTING_MAP, &key);
}

#ifdef IS_BPF_HOST

/**
 * Redirect IPv4 PIP ingress traffic to the endpoint.
 * @arg ctx:      packet
 * @arg seclabel: identity of the source
 * @arg ip4:      ipv4 header
 *
 * Return CTX_ACT_OK if the packet needs further processing.
 *        Or a possitive code returned by bpf_redirect where no futher processing needed.
 *        A negative DROP_* code on error.
 */
static __always_inline int google_try_pip_ingress_redirect4(struct __ctx_buff *ctx, __u32 seclabel, struct iphdr *ip4)
{
	struct endpoint_key ep_key = {};
	struct endpoint_info *ep;
	const struct multi_nic_dev_info *dev __maybe_unused;
	union macaddr *dmac __maybe_unused;
	struct pip_routing_entry *dst_entry = __pip_routing_lookup4(ip4->daddr);
	struct pip_routing_entry *src_entry = __pip_routing_lookup4(ip4->saddr);

	if (dst_entry != NULL) {
		ep_key.ip4 = dst_entry->ip4;
		ep_key.family = dst_entry->family;
		ep = map_lookup_elem(&ENDPOINTS_MAP, &ep_key);
		if (ep == NULL) {
			return DROP_UNROUTABLE;
		}

		// Check multinic tables to ensure parent device of destination matches current device.
		if(ep->flags & ENDPOINT_F_MULTI_NIC_VETH) {
#ifdef ENABLE_GOOGLE_MULTI_NIC
			dmac = (union macaddr *)&ep->mac;
			dev = lookup_multi_nic_dev(dmac);
			if (dev == NULL || dev->ifindex != NATIVE_DEV_IFINDEX)
			{
				// Recieved traffic intended for a multinic veth endpoint on a
				// different native/parent device. Drop it.
				return DROP_UNROUTABLE;
			}
#endif
		} else if (DIRECT_ROUTING_DEV_IFINDEX != NATIVE_DEV_IFINDEX) {
			// Recieved traffic intended for default network on additional network interface. Drop it.
			return DROP_UNROUTABLE;
		}
		return redirect_google_ep(ctx, seclabel, ip4, ep);
	}

	if (DIRECT_ROUTING_DEV_IFINDEX != NATIVE_DEV_IFINDEX) {
		return CTX_ACT_OK;
	}

	// Redirect packet to the endpoint when on the default network and the src is a Persistent IP on the same node.
	// We must bypass the kernel to avoid it identifying the packet as a Martian packet and dropping it.
	if (src_entry != NULL){
		ep_key.ip4 = src_entry->ip4;
		ep_key.family = src_entry->family;
		ep = map_lookup_elem(&ENDPOINTS_MAP, &ep_key);
		if (ep == NULL) {
			return DROP_UNROUTABLE;
		}
		if (ep->flags & ENDPOINT_F_MULTI_NIC_VETH){
			// Recieved traffic intended for additional network on default interface. Drop it.
			return DROP_UNROUTABLE;
		}

		ep = lookup_ip4_endpoint(ip4);
		if(ep) {
			// If the destination is on the same node, verify it is not a multi nic endpoint.
			// If it is, drop it to ensure network isolation.
			if (ep->flags & ENDPOINT_F_MULTI_NIC_VETH){
				return DROP_UNROUTABLE;
			}

			return redirect_google_ep(ctx, seclabel, ip4, ep);
		}
	}

	return CTX_ACT_OK;
}

#endif /* IS_BPF_HOST */

#ifdef IS_BPF_LXC

/**
 * Check if the IPv4 is a PIP attached to the current endpoint.
 * Must be called from bpf_lxc context where LXC_ID is defined.
 * @arg addr: IPv4 IP
 *
 * Return true or false.
 */
static __always_inline bool __is_endpoint_pip4(__be32 addr)
{
	struct endpoint_key ep_key = {};
	struct endpoint_info *ep;
	struct pip_routing_entry *entry = __pip_routing_lookup4(addr);

	if (entry == NULL) {
		return false;
	}

	ep_key.ip4 = entry->ip4;
	ep_key.family = entry->family;
	ep = map_lookup_elem(&ENDPOINTS_MAP, &ep_key);
	if (ep == NULL) {
		return false;
	}

	return ep->lxc_id == LXC_ID;
}

/**
 * Redirect IPv4 PIP egress traffic to the parent device or local endpoint.
 * @arg ctx:      packet
 * @arg ip4:      ipv4 header
 *
 * Return CTX_ACT_OK if the packet needs further processing.
 *        Or a possitive code returned by bpf_redirect where no futher processing needed.
 *        A negative DROP_* code on error.
 */
static __always_inline int
google_try_pip_egress_redirect4(struct __ctx_buff *ctx __maybe_unused,
			       struct iphdr *ip4 __maybe_unused)
{
	int ret;
	__u8 *smac;
	__u8 *dmac;
	int ifindex;
	struct endpoint_key ep_key __maybe_unused = {};
	struct endpoint_info *ep __maybe_unused;
	struct pip_routing_entry *entry __maybe_unused;
	union macaddr parent_mac __maybe_unused = PARENT_DEV_MAC;
	union macaddr def_mac __maybe_unused = NATIVE_DEV_MAC_BY_IFINDEX(DIRECT_ROUTING_DEV_IFINDEX);

#if defined(MULTI_NIC_DEVICE_TYPE)
#if MULTI_NIC_DEVICE_TYPE == EP_DEV_TYPE_INDEX_MULTI_NIC_VETH
	if (!__is_endpoint_pip4(ip4->saddr)) {
		return CTX_ACT_OK;
	}

	smac = (__u8 *) &parent_mac.addr;
	dmac = NULL;
	ifindex = PARENT_DEV_IFINDEX;
#else
	// Persistent IP is not supported on non-veth multi-nic endpoints, do nothing.
	return CTX_ACT_OK;
#endif
#else
	/* Logic flowchart for Persistent IP egress on default network:
	* 	S(Non-PIP)
	* 	| --> D(PIP)
	* 		| --> local-endpoint // Redirect to eth0
	* 		| --> non-local-endpoint // Passthrough
	* 	| --> D(Non-PIP) // Passthrough
	*
 	* 	S(PIP)
	* 	| --> D(Any) // Redirect to eth0
	*/
	if (!__is_endpoint_pip4(ip4->saddr)) {
		entry =  __pip_routing_lookup4(ip4->daddr);
		if (entry == NULL) {
			return CTX_ACT_OK;
		}
	}

	// Redirect packet to eth0 when on the default network.
	// We must bypass the kernel to avoid it identifying the packet as a Martian packet and dropping it.
	smac = def_mac.addr;
	dmac = NULL;
	ifindex = DIRECT_ROUTING_DEV_IFINDEX;
#endif
	ret = ipv4_l3(ctx, ETH_HLEN, smac, dmac, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;

	return ctx_redirect(ctx, ifindex, 0);
}

/**
 * Check if the destination IPv4 is a PIP attached to the current endpoint.
 * Must be called from bpf_lxc context where LXC_ID is defined.
 * @arg ctx:      packet
 *
 * Return true or false.
 */
static __always_inline bool is_dst_endpoint_pip4(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return false;

	return __is_endpoint_pip4(ip4->daddr);
}

#endif /* IS_BPF_LXC */

#endif /* ENABLE_GOOGLE_PERSISTENT_IP */
