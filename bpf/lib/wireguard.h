/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifdef ENABLE_WIREGUARD

#ifndef __WIREGUARD_H_
#define __WIREGUARD_H_

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>

#include "tailcall.h"
#include "common.h"
#include "overloadable.h"

#include "lib/proxy.h"

static __always_inline int
wg_maybe_redirect_to_encrypt(struct __ctx_buff *ctx)
{
	struct remote_endpoint_info *dst = NULL;
	struct remote_endpoint_info __maybe_unused *src = NULL;
	void *data, *data_end;
	__u16 proto = 0;
	struct ipv6hdr __maybe_unused *ip6;
	struct iphdr __maybe_unused *ip4;
	bool from_tunnel __maybe_unused = false;
	__u32 magic __maybe_unused = 0;

	if (!validate_ethertype(ctx, &proto))
		return DROP_UNSUPPORTED_L2;

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		if (!revalidate_data(ctx, &data, &data_end, &ip6))
			return DROP_INVALID;
#ifdef ENABLE_NODE_ENCRYPTION
		/* Previously, ICMPv6 NA (reply to NS) was sent over cilium_wg0,
		 * which resulted in neigh entry not being created due to
		 * IFF_POINTOPOINT | IFF_NOARP set on cilium_wg0. Therefore,
		 * NA should not be sent over WG.
		 */
		if (ip6->nexthdr == IPPROTO_ICMPV6) {
			__u8 icmp_type;

			if (data + sizeof(*ip6) + ETH_HLEN +
			    sizeof(struct icmp6hdr) > data_end)
				return DROP_INVALID;

			if (icmp6_load_type(ctx, ETH_HLEN + sizeof(struct ipv6hdr),
					    &icmp_type) < 0)
				return DROP_INVALID;

			if (icmp_type == ICMP6_NA_MSG_TYPE)
				goto out;
		}
#endif
		dst = lookup_ip6_remote_endpoint((union v6addr *)&ip6->daddr, 0);
		src = lookup_ip6_remote_endpoint((union v6addr *)&ip6->saddr, 0);
		break;
#endif
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
# if defined(TUNNEL_MODE) && defined(WIREGUARD_ENCAP)
		/* A rudimentary check (inspired by is_enap()) whether a pkt
		 * is coming from tunnel device. In tunneling mode WG needs to
		 * encrypt such pkts, so that src sec ID can be transfered.
		 *
		 * This also handles IPv6, as IPv6 pkts are encapsulated w/
		 * IPv4 tunneling.
		 */
		if (ip4->protocol == IPPROTO_UDP) {
			int l4_off = ETH_HLEN + ipv4_hdrlen(ip4);
			__be16 dport;

			if (l4_load_port(ctx, l4_off + UDP_DPORT_OFF, &dport) < 0) {
				/* IP fragmentation is not expected after the
				 * encap. So this is non-Cilium's pkt.
				 */
				break;
			}

			if (dport == bpf_htons(TUNNEL_PORT)) {
				from_tunnel = true;
				break;
			}
		}
# endif /* TUNNEL_MODE && WIREGUARD_ENCAP */
		dst = lookup_ip4_remote_endpoint(ip4->daddr, 0);
		src = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		break;
#endif
	default:
		goto out;
	}

	/* Redirect to the WireGuard tunnel device if the encryption is
	 * required.
	 *
	 * After the packet has been encrypted, the WG tunnel device
	 * will set the MARK_MAGIC_WG_ENCRYPTED skb mark. So, to avoid
	 * looping forever (e.g., bpf_host@eth0 => cilium_wg0 =>
	 * bpf_host@eth0 => ...; this happens when eth0 is used to send
	 * encrypted WireGuard UDP packets), we check whether the mark
	 * is set before the redirect.
	 */
	if ((ctx->mark & MARK_MAGIC_WG_ENCRYPTED) == MARK_MAGIC_WG_ENCRYPTED)
		goto out;

#if defined(TUNNEL_MODE) && defined(WIREGUARD_ENCAP)
	if (from_tunnel)
		goto encrypt;
#endif /* TUNNEL_MODE && WIREGUARD_ENCAP */

#ifndef ENABLE_NODE_ENCRYPTION
	/* A pkt coming from L7 proxy (i.e., Envoy or the DNS proxy on behalf of
	 * a client pod) has src IP addr of a host, but not of the client pod
	 * (if
	 * --dnsproxy-enable-transparent-mode=false). Such a pkt must be
	 *  encrypted.
	 */
	magic = ctx->mark & MARK_MAGIC_HOST_MASK;
	if (magic == MARK_MAGIC_PROXY_INGRESS || magic == MARK_MAGIC_PROXY_EGRESS)
		goto maybe_encrypt;
#if defined(TUNNEL_MODE)
	/* In tunneling mode the mark might have been reset. Check TC index instead.
	 */
	if (tc_index_from_ingress_proxy(ctx) || tc_index_from_egress_proxy(ctx))
		goto maybe_encrypt;
#endif /* TUNNEL_MODE */

	/* Unless node encryption is enabled, we don't want to encrypt
	 * traffic from the hostns (an exception - L7 proxy traffic).
	 *
	 * NB: if iptables has SNAT-ed the packet, its sec id is HOST_ID.
	 * This means that the packet won't be encrypted. This is fine,
	 * as with --encrypt-node=false we encrypt only pod-to-pod packets.
	 */
	if (!src || src->sec_identity == HOST_ID)
		goto out;
#endif /* !ENABLE_NODE_ENCRYPTION */

	/* We don't want to encrypt any traffic that originates from outside
	 * the cluster.
	 * Without this check, that may happen for the egress gateway, when
	 * reply traffic arrives from the cluster-external server and goes to
	 * the client pod.
	 */
	if (!src || !identity_is_cluster(src->sec_identity))
		goto out;

maybe_encrypt: __maybe_unused
	/* Redirect to the WireGuard tunnel device if the encryption is
	 * required.
	 */
	if (dst && dst->key) {
encrypt: __maybe_unused
		return ctx_redirect(ctx, WG_IFINDEX, 0);
	}

out:
	return CTX_ACT_OK;
}

#endif /* __WIREGUARD_H_ */

#endif /* ENABLE_WIREGUARD */
