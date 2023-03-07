/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_ENCAP_H_
#define __LIB_ENCAP_H_

#include "common.h"
#include "dbg.h"
#include "trace.h"
#include "l3.h"

#if __ctx_is == __ctx_skb
#include "encrypt.h"
#endif /* __ctx_is == __ctx_skb */

#ifdef HAVE_ENCAP
static __always_inline int
encap_remap_v6_host_address(struct __ctx_buff *ctx __maybe_unused,
			    const bool egress __maybe_unused)
{
#ifdef ENABLE_ENCAP_HOST_REMAP
	struct csum_offset csum = {};
	union v6addr host_ip;
	void *data, *data_end;
	struct ipv6hdr *ip6;
	union v6addr *which;
	__u8 nexthdr;
	__u16 proto;
	__be32 sum;
	__u32 noff;
	__u64 off;
	int ret;

	validate_ethertype(ctx, &proto);
	if (proto != bpf_htons(ETH_P_IPV6))
		return 0;
	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;
	/* For requests routed via tunnel with external v6 node IP
	 * we need to remap their source address to the router address
	 * as otherwise replies are not routed via tunnel but public
	 * address instead.
	 */
	if (egress) {
		BPF_V6(host_ip, HOST_IP);
		which = (union v6addr *)&ip6->saddr;
	} else {
		BPF_V6(host_ip, ROUTER_IP);
		which = (union v6addr *)&ip6->daddr;
	}
	if (ipv6_addrcmp(which, &host_ip))
		return 0;
	nexthdr = ip6->nexthdr;
	ret = ipv6_hdrlen(ctx, &nexthdr);
	if (ret < 0)
		return ret;
	off = ((void *)ip6 - data) + ret;
	if (egress) {
		BPF_V6(host_ip, ROUTER_IP);
		noff = ETH_HLEN + offsetof(struct ipv6hdr, saddr);
	} else {
		BPF_V6(host_ip, HOST_IP);
		noff = ETH_HLEN + offsetof(struct ipv6hdr, daddr);
	}
	sum = csum_diff(which, 16, &host_ip, 16, 0);
	csum_l4_offset_and_flags(nexthdr, &csum);
	if (ctx_store_bytes(ctx, noff, &host_ip, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;
#endif /* ENABLE_ENCAP_HOST_REMAP */
	return 0;
}

static __always_inline int
__encap_with_nodeid(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
		    __u32 seclabel, __u32 dstid, __u32 vni __maybe_unused,
		    enum trace_reason ct_reason, __u32 monitor, __u32 *ifindex)
{
	__u32 node_id;
	int ret;

	/* When encapsulating, a packet originating from the local host is
	 * being considered as a packet from a remote node as it is being
	 * received.
	 */
	if (seclabel == HOST_ID)
		seclabel = LOCAL_NODE_ID;

#ifdef ENABLE_EGRESS_GATEWAY
	/* If seclabel has local scope, set the tunnel ID to zero and let
	 * the receiver do a source lookup. */
	if (seclabel >= (1 << 24))
		seclabel = 0;
#endif /* ENABLE_EGRESS_GATEWAY */

	node_id = bpf_htonl(tunnel_endpoint);

	cilium_dbg(ctx, DBG_ENCAP, node_id, seclabel);

	ret = ctx_set_encap_info(ctx, node_id, seclabel, dstid, vni, NULL, 0, false, ifindex);
	if (ret == CTX_ACT_REDIRECT)
		send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, dstid, 0, *ifindex,
				  ct_reason, monitor);

	return ret;
}

static __always_inline int
__encap_and_redirect_with_nodeid(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
				 __u32 seclabel, __u32 dstid, __u32 vni,
				 const struct trace_ctx *trace)
{
	__u32 ifindex;

	int ret = __encap_with_nodeid(ctx, tunnel_endpoint, seclabel, dstid,
				      vni, trace->reason, trace->monitor,
				      &ifindex);
	if (ret != CTX_ACT_REDIRECT)
		return ret;

	return ctx_redirect(ctx, ifindex, 0);
}

/* encap_and_redirect_with_nodeid returns CTX_ACT_OK after ctx meta-data is
 * set. Caller should pass the ctx to the stack at this point. Otherwise
 * returns CTX_ACT_REDIRECT on successful redirect to tunnel device.
 * On error returns CTX_ACT_DROP or DROP_WRITE_ERROR.
 */
static __always_inline int
encap_and_redirect_with_nodeid(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
			       __u32 seclabel, __u32 dstid,
			       const struct trace_ctx *trace)
{
	return __encap_and_redirect_with_nodeid(ctx, tunnel_endpoint, seclabel, dstid, NOT_VTEP_DST,
						trace);
}

/* __encap_and_redirect_lxc() is a variant of encap_and_redirect_lxc()
 * that requires a valid tunnel_endpoint.
 */
static __always_inline int
__encap_and_redirect_lxc(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
			 __u8 encrypt_key __maybe_unused, __u32 seclabel,
			 __u32 dstid, const struct trace_ctx *trace)
{
	__u32 ifindex __maybe_unused;
	int ret __maybe_unused;

#ifdef ENABLE_IPSEC
	if (encrypt_key)
		return set_ipsec_encrypt(ctx, encrypt_key, tunnel_endpoint,
					 seclabel);
#endif

#if !defined(ENABLE_NODEPORT) && defined(ENABLE_HOST_FIREWALL)
	/* For the host firewall, traffic from a pod to a remote node is sent
	 * through the tunnel. In the case of node --> VIP@remote pod, packets may
	 * be DNATed when they enter the remote node. If kube-proxy is used, the
	 * response needs to go through the stack on the way to the tunnel, to
	 * apply the correct reverse DNAT.
	 * See #14674 for details.
	 */
	ret = __encap_with_nodeid(ctx, tunnel_endpoint, seclabel, dstid, NOT_VTEP_DST,
				  trace->reason, trace->monitor, &ifindex);
	if (ret != CTX_ACT_REDIRECT)
		return ret;

	/* tell caller that this packet needs to go through the stack: */
	return CTX_ACT_OK;
#else
	return __encap_and_redirect_with_nodeid(ctx, tunnel_endpoint,
						seclabel, dstid, NOT_VTEP_DST, trace);
#endif /* !ENABLE_NODEPORT && ENABLE_HOST_FIREWALL */
}

#ifdef TUNNEL_MODE
/* encap_and_redirect_lxc adds IPSec metadata (if enabled) and returns the packet
 * so that it can be passed to the IP stack. Without IPSec the packet is
 * typically redirected to the output tunnel device and ctx will not be seen by
 * the IP stack.
 *
 * Returns CTX_ACT_OK when ctx needs to be handed to IP stack (eg. for IPSec
 * handling), CTX_ACT_DROP, DROP_NO_TUNNEL_ENDPOINT or DROP_WRITE_ERROR on error,
 * and finally on successful redirect returns CTX_ACT_REDIRECT.
 */
static __always_inline int
encap_and_redirect_lxc(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
		       __u8 encrypt_key, struct tunnel_key *key,
		       __u32 seclabel, __u32 dstid,
		       const struct trace_ctx *trace)
{
	struct tunnel_value *tunnel;

	if (tunnel_endpoint)
		return __encap_and_redirect_lxc(ctx, tunnel_endpoint,
						encrypt_key, seclabel, dstid,
						trace);

	tunnel = map_lookup_elem(&TUNNEL_MAP, key);
	if (!tunnel)
		return DROP_NO_TUNNEL_ENDPOINT;

#ifdef ENABLE_IPSEC
	if (tunnel->key) {
		__u8 min_encrypt_key = get_min_encrypt_key(tunnel->key);

		return set_ipsec_encrypt(ctx, min_encrypt_key, tunnel->ip4,
					 seclabel);
	}
#endif
	return __encap_and_redirect_with_nodeid(ctx, tunnel->ip4, seclabel,
						dstid, NOT_VTEP_DST, trace);
}

static __always_inline int
encap_and_redirect_netdev(struct __ctx_buff *ctx, struct tunnel_key *k,
			  __u32 seclabel, const struct trace_ctx *trace)
{
	struct tunnel_value *tunnel;

	tunnel = map_lookup_elem(&TUNNEL_MAP, k);
	if (!tunnel)
		return DROP_NO_TUNNEL_ENDPOINT;

	return __encap_and_redirect_with_nodeid(ctx, tunnel->ip4, seclabel,
						0, NOT_VTEP_DST, trace);
}
#endif /* TUNNEL_MODE */

#if defined(ENABLE_DSR) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
static __always_inline int
__encap_with_nodeid_opt(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
			__u32 seclabel, __u32 dstid, __u32 vni,
			void *opt, __u32 opt_len, bool is_ipv6,
			enum trace_reason ct_reason,
			__u32 monitor, __u32 *ifindex)
{
	__u32 node_id;
	int ret;

	/* When encapsulating, a packet originating from the local host is
	 * being considered as a packet from a remote node as it is being
	 * received.
	 */
	if (seclabel == HOST_ID)
		seclabel = LOCAL_NODE_ID;

	node_id = bpf_ntohl(tunnel_endpoint);

	cilium_dbg(ctx, DBG_ENCAP, node_id, seclabel);

	ret = ctx_set_encap_info(ctx, node_id, seclabel, dstid, vni,
				 opt, opt_len, is_ipv6, ifindex);
	if (ret == CTX_ACT_REDIRECT)
		send_trace_notify(ctx, TRACE_TO_OVERLAY, seclabel, dstid, 0, *ifindex,
				  ct_reason, monitor);

	return ret;
}

static __always_inline int
encap_and_redirect_with_nodeid_opt(struct __ctx_buff *ctx, __u32 tunnel_endpoint,
				   __u32 seclabel, __u32 dstid, __u32 vni,
				   void *opt, __u32 opt_len, bool is_ipv6,
				   const struct trace_ctx *trace)
{
	__u32 ifindex = 0;

	int ret = __encap_with_nodeid_opt(ctx, tunnel_endpoint, seclabel, dstid,
					  vni, opt, opt_len, is_ipv6,
					  trace->reason, trace->monitor, &ifindex);
	if (ret != CTX_ACT_REDIRECT)
		return ret;

	return ctx_redirect(ctx, ifindex, 0);
}

static __always_inline void
set_geneve_dsr_opt4(__be16 port, __be32 addr, struct geneve_dsr_opt4 *gopt)
{
	memset(gopt, 0, sizeof(*gopt));
	gopt->hdr.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS);
	gopt->hdr.type = DSR_GENEVE_OPT_TYPE;
	gopt->hdr.length = DSR_IPV4_GENEVE_OPT_LEN;
	gopt->addr = addr;
	gopt->port = port;
}

static __always_inline void
set_geneve_dsr_opt6(__be16 port, const union v6addr *addr,
		    struct geneve_dsr_opt6 *gopt)
{
	memset(gopt, 0, sizeof(*gopt));
	gopt->hdr.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS);
	gopt->hdr.type = DSR_GENEVE_OPT_TYPE;
	gopt->hdr.length = DSR_IPV6_GENEVE_OPT_LEN;
	ipv6_addr_copy(&gopt->addr, addr);
	gopt->port = port;
}
#endif
#endif /* HAVE_ENCAP */
#endif /* __LIB_ENCAP_H_ */
