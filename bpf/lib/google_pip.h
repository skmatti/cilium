#ifndef __LIB_GOOGLE_PIP_H_
#define __LIB_GOOGLE_PIP_H_

#include "google_maps.h"

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
	const struct multi_nic_dev_info *dev;
	union macaddr *dmac;
	struct pip_routing_entry *entry = __pip_routing_lookup4(ip4->daddr);

	if (entry == NULL) {
		return CTX_ACT_OK;
	}

	ep_key.ip4 = entry->ip4;
	ep_key.family = entry->family;
	ep = map_lookup_elem(&ENDPOINTS_MAP, &ep_key);
	/* TODO(b/292558915): Support default network */
	if (ep == NULL || !(ep->flags & ENDPOINT_F_MULTI_NIC_VETH)) {
		return DROP_UNROUTABLE;
	}

	dmac = (union macaddr *)&ep->mac;
	dev = lookup_multi_nic_dev(dmac);
	if (dev == NULL || dev->ifindex != NATIVE_DEV_IFINDEX)
	{
		// Recieved traffic intended for a multinic veth endpoint on a
		// different native/parent device. Drop it.
		return DROP_UNROUTABLE;
	}
	return __redirect_multinic_ep(ctx, ETH_HLEN, seclabel, ip4, ep);
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
 * Redirect IPv4 PIP egress traffic to the parent device.
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

#ifdef MULTI_NIC_DEVICE_TYPE
#if MULTI_NIC_DEVICE_TYPE == EP_DEV_TYPE_INDEX_MULTI_NIC_VETH
{
	union macaddr parent_mac = PARENT_DEV_MAC;
	int ret;

	if (!__is_endpoint_pip4(ip4->saddr)) {
		return CTX_ACT_OK;
	}
	ret = ipv4_l3(ctx, ETH_HLEN, (__u8 *) &parent_mac.addr, NULL, ip4);
	if (unlikely(ret != CTX_ACT_OK))
		return ret;
	return ctx_redirect(ctx, PARENT_DEV_IFINDEX, 0);
}
#endif
#endif
    return  CTX_ACT_OK;
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


#endif  // __LIB_GOOGLE_PIP_H_
