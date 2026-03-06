#pragma once

#include "lib/google/hooks_common.h"
#include "lib/google/geneve_common.h"

#ifdef ENABLE_GOOGLE_GENEVE

# include "lib/common.h"
# include "lib/jhash.h"
# include "lib/lb.h"
# include "lib/stubs.h"
# include "lib/pcap.h"

# if __ctx_is == __ctx_skb
#  include "lib/fib.h"
# endif /* __ctx_is == __ctx_skb */

# ifdef ENABLE_IPV4
/*
 * Replacement of the ctx_set_tunnel_key.
 */
static __always_inline int google_ctx_set_tunnel_key(
	struct __ctx_buff *ctx __maybe_unused, const struct bpf_tunnel_key *from,
	__u32 size, __u32 flags __maybe_unused)
{
	struct geneve_metadata *metadata = geneve_get_metadata(GENEVE_DIR_EGRESS);

	if (unlikely(!metadata || size > sizeof(struct bpf_tunnel_key)))
		return DROP_INVALID;
	memcpy(&metadata->tunnel_key, from, size);
	return geneve_set_metadata(metadata, GENEVE_DIR_EGRESS);
}

static __always_inline int google_ctx_set_tunnel_opt(
	struct __ctx_buff *ctx __maybe_unused, void *opt, __u32 size)
{
	struct geneve_metadata *metadata = geneve_get_metadata(GENEVE_DIR_EGRESS);
	int ret;

	if (unlikely(!metadata))
		return DROP_INVALID;
	ret = geneve_set_options_to_metadata(metadata, opt, size);
	if (unlikely(ret < 0))
		return ret;
	return geneve_set_metadata(metadata, GENEVE_DIR_EGRESS);
}

/*
 * Flow hash from 5-tuple if ports are available. Otherwise, hash using 3-tuple.
 */
static __always_inline __u32
geneve_flow_hash4(struct __ctx_buff *ctx, struct iphdr *ip4)
{
	struct ipv4_ct_tuple l4tuple = { 0 };
	int l4_offset = 0;
	__u32 a, b, c;
	int ret __maybe_unused;

	// We want to support any protocol here, so no need to check return code here.
	// The 3-tuple (saddr, daddr, protocol) should be extracted regardless.
	ret = lb4_extract_tuple(ctx, ip4, ETH_HLEN, &l4_offset, &l4tuple);
	a = l4tuple.saddr;
	b = l4tuple.daddr;
	c = l4tuple.nexthdr;
	__jhash_mix(a, b, c);
	a += HASH_INIT4_SEED;
	b += ((__u32)l4tuple.dport << 16) | l4tuple.sport;
	__jhash_final(a, b, c);
	return c;
}

// Encapsulates the given ctx_buff with Geneve.
// The encapsulated header will be stored to `hdr` as well.
static __always_inline int
geneve_encap4(struct __ctx_buff *ctx, struct geneve_metadata *metadata,
	      struct geneve_encaphdr4 *hdr)
{
	__u64 flags __maybe_unused;
	__u16 sport;
	struct iphdr *ip4;
	struct ethhdr *eth;
	void *data, *data_end;
	__u16 hdr_len = 0;
	__u32 encoded_opt_len = 0;
	int i;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	eth = data;
	genevehdr_init(&hdr->geneve, ETH_P_IP, metadata);
	hdr_len = geneve_encaphdr4_size(hdr);

	/* https://datatracker.ietf.org/doc/html/rfc8926#section-3.3:
	 * To encourage an even distribution of flows across multiple links, the source port SHOULD be
	 * calculated using a hash of the encapsulated packet headers using, for example, a traditional 5-tuple.
	 *
	 * The hash is ORed with 0x8000 to make the port high enough to not conflict with priveleged ports.
	 * Set LSB to 1 (odd port) for reply traffic.
	 * Set LSB to 0 (even port) for non-reply traffic.
	 */
	sport = (csum_fold(geneve_flow_hash4(ctx, ip4)) & 0xFFFE) | 0x8000;
	hdr->udp.source = bpf_htons(sport);
	hdr->udp.dest = bpf_htons(TUNNEL_PORT);
	hdr->udp.len = bpf_htons(
		bpf_ntohs(ip4->tot_len) + hdr_len - sizeof(struct iphdr));
	hdr->udp.check = 0; /* we use BPF_F_ZERO_CSUM_TX */

	hdr->ip.version = IPVERSION;
	hdr->ip.ttl = IPDEFTTL;
	hdr->ip.tos = ip4->tos;
	hdr->ip.id = ip4->id;
	if (metadata->tunnel_key.local_ipv4)
		hdr->ip.saddr = bpf_htonl(metadata->tunnel_key.local_ipv4);
	else
		hdr->ip.saddr = IPV4_DIRECT_ROUTING;
	hdr->ip.daddr = bpf_htonl(metadata->tunnel_key.remote_ipv4);
	hdr->ip.protocol = IPPROTO_UDP;
	hdr->ip.ihl = sizeof(struct iphdr) >> 2;
	hdr->ip.tot_len = bpf_htons(bpf_ntohs(ip4->tot_len) + hdr_len);
	hdr->ip.check =
		csum_fold(csum_diff(NULL, 0, &hdr->ip, sizeof(hdr->ip), 0));

	eth->h_proto = bpf_htons(ETH_P_IP);

	flags = geneve_ctx_adjust_hroom_flags();
	flags |= BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
	if (ip4->protocol == IPPROTO_UDP) {
		// UDP GSO must have BPF_F_ADJ_ROOM_FIXED_GSO.
		flags |= BPF_F_ADJ_ROOM_FIXED_GSO;
	}

	if (ctx_adjust_hroom(ctx, hdr_len, BPF_ADJ_ROOM_MAC, flags))
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, ETH_HLEN, hdr, sizeof(struct geneve_encaphdr4),
			    BPF_F_INVALIDATE_HASH) < 0)
		return DROP_INVALID;
	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	// Start to store geneve options.
#  pragma unroll
	for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++) {
		if (i < metadata->opt_count) {
			struct geneve_opt_hdr *opt =
				(struct geneve_opt_hdr
					 *)(metadata->raw_opt_data +
					    i * GENEVE_OPT_MAX_LENGTH);
			__u32 opt_len = 4 * (__u32)__geneve_opt_len(opt);

			// Skip if the option length is too long.
			if (opt_len > GENEVE_OPT_MAX_LENGTH)
				return DROP_INVALID;
			if (data + ETH_HLEN + sizeof(struct geneve_encaphdr4) +
				    encoded_opt_len + opt_len >
			    data_end)
				return DROP_INVALID;

#  if __ctx_is == __ctx_skb
			if (ctx_store_bytes(
				    ctx,
				    ETH_HLEN + sizeof(struct geneve_encaphdr4) +
					    encoded_opt_len,
				    opt, opt_len, BPF_F_INVALIDATE_HASH) < 0)
				return DROP_INVALID;
#  elif __ctx_is == __ctx_xdp
			{
				// In XDP, ctx_store_bytes uses memcpy which requires constant length.
				// Copy manually byte-by-byte (or 4-byte chunks).
				// opt_len is max (32 * 1) * 4 = 128 bytes.
				void *pkt_data =
					data + ETH_HLEN +
					sizeof(struct geneve_encaphdr4) +
					encoded_opt_len;
				__u32 k;

				if (pkt_data + opt_len > data_end)
					return DROP_INVALID;

#   pragma unroll
				for (k = 0; k < GENEVE_OPT_MAX_LENGTH; k++) {
					if (k < opt_len) {
						if (pkt_data + k + 1 > data_end)
							break;
						((__u8 *)pkt_data)[k] =
							((__u8 *)opt)[k];
					}
				}
			}
#  endif

			encoded_opt_len += opt_len;
		}
	}
	if (sizeof(struct geneve_encaphdr4) + encoded_opt_len != hdr_len)
		return DROP_INVALID;
	return CTX_ACT_REDIRECT;
}

static __always_inline int
geneve_decap4(struct __ctx_buff *ctx, struct geneve_metadata *metadata)
{
	struct geneve_encaphdr4 hdr = { 0 };
	__u16 hdr_len = 0;

	if (ctx_load_bytes(ctx, ETH_HLEN, &hdr, sizeof(hdr)) < 0)
		return DROP_INVALID;

	metadata->tunnel_key.local_ipv4 = hdr.ip.saddr;
	metadata->tunnel_key.remote_ipv4 = hdr.ip.daddr;
	metadata->tunnel_key.tunnel_id = genevehdr_vni(&hdr.geneve);
	ctx_set_xfer(ctx, XFER_PKT_GOOGLE_BPF_GENEVE);
	hdr_len = geneve_encaphdr4_size(&hdr);

	// Extract Geneve options one by one.
	if (hdr.geneve.opt_len > 0) {
		__u32 total_opt_len = 4 * (__u32)hdr.geneve.opt_len;
		__u32 decoded_opt_len = 0;
		int i;

#  pragma unroll
		for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++) {
			if (decoded_opt_len < total_opt_len) {
				__u32 opt_len = geneve_decode_opt4(
					ctx,
					ETH_HLEN + sizeof(hdr) + decoded_opt_len,
					metadata->raw_opt_data,
					i * GENEVE_OPT_MAX_LENGTH);

				// Drop the packet when there is pending option to be decoded, but the decode function
				// returns error. The packet is malformed in this case.
				if (!opt_len)
					return DROP_INVALID;
				decoded_opt_len += opt_len;
				metadata->opt_count++;
			}
		}
		// Total option length in Geneve packet header doesn't match the sum of option
		// data length we found.
		if (decoded_opt_len != total_opt_len)
			return DROP_INVALID;
	}

	// Store geneve metadata.
	if (geneve_set_metadata(metadata, GENEVE_DIR_INGRESS) < 0)
		return DROP_INVALID;

	// Remove geneve header from the packet and adjust the packet head room.
#  if __ctx_is == __ctx_skb
	{
		__u64 flags =
			geneve_ctx_adjust_hroom_flags() | BPF_F_ADJ_ROOM_FIXED_GSO;

		if (ctx_adjust_hroom(ctx, -(__s32)hdr_len, BPF_ADJ_ROOM_MAC, flags))
			return DROP_INVALID;
	}
#  elif __ctx_is == __ctx_xdp
	{
		// The cilium ctx_adjust_hroom for XDP is pretty hacky, it only supports
		// adjusting at BPF_ADJ_ROOM_NET with a limited selection of adjustment size.
		// Therefore we adjust head by ourselves here.
		struct ethhdr eth;

		if (ctx_load_bytes(ctx, 0, &eth, ETH_HLEN) < 0)
			return DROP_INVALID;
		if (xdp_adjust_head(ctx, (__s32)hdr_len))
			return DROP_INVALID;
		if (ctx_store_bytes(ctx, 0, &eth, ETH_HLEN, BPF_F_INVALIDATE_HASH) <
		    0)
			return DROP_INVALID;
	}
#  else
	return DROP_INVALID;
#  endif

	{
		void *data, *data_end;
		struct iphdr *ip4;
		// We need to pull the skb once after decapsulation to make sure the new IP header
		// is linear in memory.
		// This step is no-op in XDP as it's already linear there.
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
	}
	return CTX_ACT_OK;
}

/* geneve_try_decap4 tries to decapsulate the incoming packet as a GENEVE packet.
 * Returns HOOK_ACT_CONTINUE when:
 *    - when the given packet is not a geneve packet;
 *    - or we do not plan to decapsulate in this stage (e.g. we do not decap certain geneve packets in XDP)
 * Other return code is also possible.
 */
static __always_inline int geneve_try_decap4(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	if (!geneve_is_encapped_to_node4(ctx, ip4))
		return HOOK_ACT_CONTINUE;

	return tail_call_internal(ctx, CILIUM_CALL_GOOGLE_IPV4_GENEVE_DECAP, NULL);
}

/*
 * A tail call which decapsulate the given GENEVE IPv4 packet.
 * When the geneve decapsulation is successful, geneve_get_current_bpf_program() will be
 * set to GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY, then the problem will be tail-called back
 * to the from-lxc/from-netdev section entry.
 * Return DROP_INVALID when the given packet is not a GENEVE packet, it will be dropped.
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_GOOGLE_IPV4_GENEVE_DECAP)
int tail_geneve_decap4(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct geneve_metadata metadata = { 0 };
	__u32 src_sec_identity = 0;
	__s8 ext_err = 0;
	int ret;

	struct trace_ctx trace = {
		.reason = TRACE_REASON_UNKNOWN,
		.monitor = 0,
	};

	send_trace_notify(ctx, TRACE_FROM_NETWORK, UNKNOWN_ID, UNKNOWN_ID,
			  TRACE_EP_ID_UNKNOWN,
			  NATIVE_DEV_IFINDEX, trace.reason, trace.monitor);

	ret = geneve_decap4(ctx, &metadata);
	if (IS_ERR(ret))
		goto out;
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto out;
	}
	// After we successfully decapped the packet, we consider we are in bpf_overlay now.
	if (geneve_set_current_bpf_program(GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY) <
	    0) {
		ret = DROP_WRITE_ERROR;
		goto out;
	}

	{
		struct remote_endpoint_info *info;
		__u16 proto;

#  ifndef ENABLE_HIGH_SCALE_IPCACHE
		/* preserve skb->cb for hs-ipcache, from-netdev is passing info */
		bpf_clear_meta(ctx);
#  endif
		ctx_skip_nodeport_clear(ctx);

		if (!validate_ethertype(ctx, &proto)) {
			/* Pass unknown traffic to the stack */
			ret = CTX_ACT_OK;
			goto out;
		}

		cilium_dbg(ctx, DBG_DECAP, metadata.tunnel_key.tunnel_id,
			   metadata.tunnel_key.tunnel_label);

		/* Lookup source identity here.
		 * In OSS implementation, this value is from get_id_from_tunnel_id() (see bpf_overlay.c)
		 * However, in GDC-ag 1.13, the tunnel_id is always zero (default VPC ID).
		 * This means we cannot trust the source identity from tunnel ID here.
		 */
		info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		if (info)
			src_sec_identity = info->sec_identity;

		/* Any node encapsulating will map any HOST_ID source to be
		 * presented as REMOTE_NODE_ID, therefore any attempt to signal
		 * HOST_ID as source from a remote node can be dropped.
		 */
		if (src_sec_identity == HOST_ID) {
			ret = DROP_INVALID_IDENTITY;
			goto out;
		}

		/* Store the identity read from VNI to metadata, OSS Cilium
		 * is using CB_SRC_LABEL to store source identity.
		 * However, also note that this field may not be used in bpf_host
		 * which will explicitly call resolve_srcid_ipv4() in
		 * do_netdev() to resolve the source identity.
		 */
		ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
	}

	/* Prevent invalid size of register spill on data_end (verifier error). */
	data = NULL;
	data_end = NULL;

	{
		enum trace_point obs_point = TRACE_FROM_OVERLAY;

#  if GOOGLE_IPSEC_MODE == GOOGLE_IPSEC_MODE_SOFTWARE
		obs_point = TRACE_FROM_STACK;
#  endif
		send_trace_notify(
			ctx, obs_point, src_sec_identity, UNKNOWN_ID,
			TRACE_EP_ID_UNKNOWN, ctx->ingress_ifindex,
			TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);
	}

	ret = HOOK_ACT_CONTINUE;
	if (geneve_set_metadata(&metadata, GENEVE_DIR_INGRESS) < 0)
		ret = DROP_WRITE_ERROR;
out:
	if (ret != HOOK_ACT_CONTINUE && IS_ERR(ret))
		return send_drop_notify_error_ext(
			ctx, src_sec_identity, ret, ext_err, CTX_ACT_DROP,
			METRIC_INGRESS);

#  if __ctx_is == __ctx_xdp
	// For XDP, we just exit here, and the packet will be processed in TC later.
	// Note since we have tail-called to here, we cannot simply return HOOK_ACT_CONTINUE.
	ctx_move_xfer(ctx);
	return CTX_ACT_OK;
#  else
	// The packet has been successfully decapped, recirculate the packet.
	return tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_NETDEV, NULL);
#  endif
}

# endif /* ENABLE_IPV4 */

/*
 * Redirect encapped packet to direct routing device.
 * When IPSec is enabled, this will return CTX_ACT_OK to make sure the packet go out via kernel.
 */
static __always_inline int __google_encap_redirect_v4(
	struct __ctx_buff *ctx, __u32 dstid __maybe_unused,
	int ifindex __maybe_unused, const struct trace_ctx *trace __maybe_unused)
{
	int ret = DROP_WRITE_ERROR;

# if defined(ENABLE_IPV4) && defined(ENCAP_IFINDEX)
	if (ifindex == ENCAP_IFINDEX) {
		// ifindex typically should always be ENCAP_IFINDEX for the packet to be redirected to the overlay interface.
		// However, ifindex is set to zero in some cases in encap.h when __ctx_is == __ctx_xdp
#  if __ctx_is == __ctx_skb
#   if GOOGLE_IPSEC_MODE == GOOGLE_IPSEC_MODE_DISABLED
		void *data, *data_end;
		struct iphdr *ip4;
		__s8 ext_err = 0;
		int oif;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		ifindex = DIRECT_ROUTING_DEV_IFINDEX;
		ret = fib_redirect_v4(ctx, ETH_HLEN, ip4, true, false, &ext_err, &oif);
		goto to_redirect;
#   else  /* GOOGLE_IPSEC_MODE */
		// If IPSec is enabled, send the packet back to kernel for IPSec encryption.
		send_trace_notify(
			ctx, TRACE_TO_STACK, SECLABEL, dstid, 0, ifindex,
			TRACE_REASON_UNKNOWN, 0);
		return CTX_ACT_OK;
#   endif /* GOOGLE_IPSEC_MODE */
#  else	  /* __ctx_is == __ctx_xdp */
		ctx_move_xfer(ctx);
		ifindex = DIRECT_ROUTING_DEV_IFINDEX;
		ret = ctx_redirect(ctx, ifindex, 0);
		goto to_redirect;
#  endif  /* __ctx_is == __ctx_skb */
	}
# else
	// IPv6 is not supported.
	__throw_build_bug();
# endif /* ENABLE_IPV4 */

__maybe_unused to_redirect:
	if (likely(ret == CTX_ACT_REDIRECT)) {
		cilium_capture_out(ctx);
		send_trace_notify(
			ctx, TRACE_TO_NETWORK, SECLABEL, dstid, 0, ifindex,
			TRACE_REASON_UNKNOWN, 0);
	} else if (IS_ERR(ret))
		return send_drop_notify_error(
			ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
	return ret;
}

/*
 * A replacement of the original ctx_get_tunnel_key()
 */
static __always_inline __maybe_unused int google_ctx_get_tunnel_key(
	struct __ctx_buff *ctx __maybe_unused, struct bpf_tunnel_key *to,
	__u32 size, __u32 flags __maybe_unused)
{
	const enum geneve_bpf_program_id program_id =
		geneve_get_current_bpf_program();
	struct geneve_metadata *metadata;

	// Align with kernel behavior, get corresponding metadata for different direction.
	if (program_id == GENEVE_BPF_PROGRAM_ID_TO_OVERLAY)
		metadata = geneve_get_metadata(GENEVE_DIR_EGRESS);
	else
		metadata = geneve_get_metadata(GENEVE_DIR_INGRESS);
	if (!metadata)
		return DROP_INVALID;
	if (size > sizeof(struct bpf_tunnel_key))
		return DROP_INVALID;
	memcpy(to, &metadata->tunnel_key, size);
	return CTX_ACT_OK;
}

/*
 * A replacement of the original ctx_set_encap_info()
 */
static __always_inline __maybe_unused int google_ctx_set_encap_info(
	struct __ctx_buff *ctx __maybe_unused, __u32 src_ip,
	__be16 src_port __maybe_unused, __u32 node_id, __u32 seclabel,
	__u32 vni __maybe_unused, void *opt, __u32 opt_len)
{
	struct geneve_metadata metadata = { 0 };
	int ret;

# ifdef ENABLE_VTEP
	if (vni != NOT_VTEP_DST)
		metadata.tunnel_key.tunnel_id = get_tunnel_id(vni);
	else
# endif /* ENABLE_VTEP */
		metadata.tunnel_key.tunnel_id = get_tunnel_id(seclabel);

	if (src_ip != 0)
		metadata.tunnel_key.local_ipv4 = bpf_ntohl(src_ip);
	metadata.tunnel_key.remote_ipv4 = node_id;
	metadata.tunnel_key.tunnel_ttl = IPDEFTTL;

	// Set geneve options
	ret = geneve_set_options_to_metadata(&metadata, opt, opt_len);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;
	// Persist GENEVE metadata to map.
	ret = geneve_set_metadata(&metadata, GENEVE_DIR_EGRESS);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;

	return CTX_ACT_REDIRECT;
}

static __always_inline int google_ctx_redirect_to_overlay(struct __ctx_buff *ctx)
{
	int ret = geneve_set_current_bpf_program(GENEVE_BPF_PROGRAM_ID_TO_OVERLAY);

	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;
	return tail_call_internal(ctx, CILIUM_CALL_GOOGLE_IPV4_GENEVE_ENCAP, NULL);
}

/*
 * Replacement of ctx_redirect() when eBPF GENEVE is on.
 */
static __always_inline int google_geneve_ctx_redirect(
	struct __ctx_buff *ctx __maybe_unused, int ifindex, const __u32 flags)
{
	const enum geneve_bpf_program_id program_id =
		geneve_get_current_bpf_program();

	/*
	 * Only do the following when we have not gone through the overlay redirection
	 * logic, and the packet is heading to the egress of the overlay interface.
	 * This makes sure the packet is not going through a loop.
	 * The loop may happen in __google_encap_redirect_v4()/fib_redirect_v4(), where
	 * ctx_redirect() is called again.
	 */
# ifdef ENCAP_IFINDEX
	if (program_id != GENEVE_BPF_PROGRAM_ID_TO_OVERLAY &&
	    ifindex == ENCAP_IFINDEX && flags == 0)
		return google_ctx_redirect_to_overlay(ctx);
# endif

	// The original redirection logic for both XDP and TC.
# if __ctx_is == __ctx_xdp
	if ((__u32)ifindex == ctx->ingress_ifindex)
		return XDP_TX;
# endif
	return redirect(ifindex, flags);
}

/*
 * A tailcall which encapsulate the packet into a geneve packet,
 * then sending it out via DIRECT ROUTING DEVICE by using bpf_redirect().
 *
 * Note:
 * The packet may go through CILIUM_CALL_IPV4_NODEPORT_NAT_FWD in this function
 * for SNAT/Conntracking etc., where the packet will recirculate to the interface before encapsulation.
 * We need to make sure the GENEVE encap hook (i.e. geneve_redirect_to_overlay_if_encapped) is invoked
 * in the CILIUM_CALL_IPV4_FROM_NETDEV __section_tail in the corresponding bpf program,
 * so that the packet will be back here for encapsulation.
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_GOOGLE_IPV4_GENEVE_ENCAP)
int tail_geneve_encap_and_redirect_to_overlay(
	struct __ctx_buff *ctx)
{
	const enum geneve_bpf_program_id program_id =
		geneve_get_current_bpf_program();
	struct geneve_metadata *metadata;
	bool snat_done __maybe_unused = ctx_snat_done(ctx);
	struct trace_ctx __maybe_unused trace;
	__u32 src_sec_identity = UNKNOWN_ID;
	int ret = CTX_ACT_OK;
	__be16 __maybe_unused proto = 0;
	__s8 ext_err = 0;
	struct geneve_encaphdr4 hdr __maybe_unused = { 0 };

	/* We only redirect packet after we enter the overlay domain.
	 * A packet doesn't have correct metadata should not arrive here.
	 */
	if (program_id != GENEVE_BPF_PROGRAM_ID_TO_OVERLAY)
		return DROP_INVALID;
	metadata = geneve_get_metadata(GENEVE_DIR_EGRESS);
	if (!geneve_metadata_is_set(metadata))
		return DROP_INVALID;

	/* Load the ethertype just once: */
	validate_ethertype(ctx, &proto);

	// Not support by GDC-ag.
# if defined(ENABLE_BANDWIDTH_MANAGER) || defined(ENABLE_CLUSTER_AWARE_ADDRESSING)
	__throw_build_bug();
# endif

	/* We might see some unexpected packets without tunnel_key (eg. IPv6 ND).
	 * No need to worry, the geneve/vxlan kernel drivers will drop them.
	 */
	src_sec_identity = get_id_from_tunnel_id(
		metadata->tunnel_key.tunnel_id, ctx_get_protocol(ctx));

	// Reset VNI.
	metadata->tunnel_key.tunnel_id = 0;

	set_identity_mark(ctx, src_sec_identity, MARK_MAGIC_OVERLAY);

# ifdef ENABLE_NODEPORT
	if (snat_done)
		goto out;

	/* handle_nat_fwd from nodeport.h start */
	ctx_store_meta(ctx, CB_NAT_FLAGS, 0);
	// Clear cluster ID as we don't use it.
	ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, 0);

	switch (proto) {
#  ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		/*
		 * Although CILIUM_CALL_IPV4_NODEPORT_NAT_FWD __section_tail is defined nodeport.h,
		 * and we cannot import nodeport.h in this file as it will cause a dependency loop
		 * (google/geneve.h -> nodeport.h -> nat.h -> encap.h -> google/geneve.h), we are
		 * pretty sure nodeport.h will be included later when ENABLE_NODEPORT is defined.
		 * Therefore the tailcall here will succeed.
		 * The program will return to here again later with `snat_done` set.
		 */
		ret = tail_call_internal(
			ctx, CILIUM_CALL_IPV4_NODEPORT_NAT_FWD, NULL);
		break;
#  endif /* ENABLE_IPV4 */
	default:
		build_bug_on(!(NODEPORT_PORT_MIN_NAT < NODEPORT_PORT_MAX_NAT));
		build_bug_on(!(NODEPORT_PORT_MIN < NODEPORT_PORT_MAX));
		build_bug_on(!(NODEPORT_PORT_MAX < NODEPORT_PORT_MIN_NAT));
		break;
	}
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(
			ctx, src_sec_identity, ret, ext_err, CTX_ACT_DROP,
			METRIC_EGRESS);
	/* handle_nat_fwd from nodeport.h end */

out:
# endif
	// At this point we should consider the packet is already heading out, i.e. this is
	// equivalent to returning CTX_ACT_OK in cil_to_overlay. The belows steps are the
	// translations of the original kernel steps.

	// Do GENEVE encapsulation with options.
# ifdef ENABLE_IPV4
	ret = geneve_encap4(ctx, metadata, &hdr);
	if (IS_ERR(ret))
		return ret;
# else
	// IPv6 is not supported yet.
	__throw_build_bug();
# endif /* ENABLE_IPV4 */

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(
			ctx, src_sec_identity, ret, ext_err, CTX_ACT_DROP,
			METRIC_EGRESS);

	// Redirect packet to eth0 (or kernel when IPSec mode == software).
	return __google_encap_redirect_v4(ctx, 0, ENCAP_IFINDEX, &trace);
}

/*
 * Check GENEVE metadata on egress direction is set. If yes, send the packet
 * out via DIRECT ROUTING interface.
 */
static __always_inline int
geneve_redirect_to_overlay_if_encapped(struct __ctx_buff *ctx)
{
	const enum geneve_bpf_program_id program_id =
		geneve_get_current_bpf_program();
	struct geneve_metadata *metadata;

	// We only redirect packet after we enter the overlay domain.
	if (program_id != GENEVE_BPF_PROGRAM_ID_TO_OVERLAY)
		return HOOK_ACT_CONTINUE;
	metadata = geneve_get_metadata(GENEVE_DIR_EGRESS);
	if (!geneve_metadata_is_set(metadata))
		return HOOK_ACT_CONTINUE;

	return tail_call_internal(ctx, CILIUM_CALL_GOOGLE_IPV4_GENEVE_ENCAP, NULL);
}

static __always_inline int geneve_reset_state(void)
{
	// Clear existing metadata from previous packets.
	if (geneve_clear_metadata(GENEVE_DIR_INGRESS) < 0 ||
	    geneve_clear_metadata(GENEVE_DIR_EGRESS) < 0)
		return DROP_WRITE_ERROR;
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_ctr_egress_start4(void)
{
	int ret = geneve_reset_state();

	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	if (geneve_set_current_bpf_program(GENEVE_BPF_PROGRAM_ID_FROM_LXC) < 0)
		return DROP_WRITE_ERROR;
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_netdev_ingress_fwd4(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_netdev_ingress_fwd4_ctx *stage_ctx)
{
	/* If this packet is decapsulated from GENEVE tunnel,
	 * then skip the multi-nic and host routing logic.
	 */
	stage_ctx->__common.go_to_endpoint =
		geneve_get_current_bpf_program() ==
		GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY;

	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_netdev_ingress_fwd4_ipsec(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_host_ingress_fwd4_ctx_common *stage_ctx_common __maybe_unused)
{
# if GOOGLE_IPSEC_MODE == GOOGLE_IPSEC_MODE_SOFTWARE
	// In some situation, e.g., the packet got recirculated after IPSec decryption,
	// it may be marked as OTHERHOST. We need to change it to HOST so that kernel won't drop it.
	ctx_change_type(ctx, PACKET_HOST);

	/* After geneve tunnel is terminated in cilium, ebpf lacks the API to
	 * "scrub" the SKB to remove stale XFRM data(skb->sp). This impacts traffic
	 * destined to node. To workaround this we redirect locally destined traffic
	 * to cilium host(which forces the kernel to scrub) when N2N encryption is
	 * enabled.
	 * TODO(b/383158433): Revert this change once HW offload is available.
	 */
	if (geneve_get_current_bpf_program() == GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY &&
	    stage_ctx_common->ep && stage_ctx_common->ep->flags & ENDPOINT_F_HOST) {
		union macaddr router_mac = THIS_INTERFACE_MAC;
		union macaddr host_mac = HOST_IFINDEX_MAC;
		void *data, *data_end;
		struct iphdr *ip4;
		int ret;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		ret = ipv4_l3(ctx, ETH_HLEN, (__u8 *)&router_mac.addr,
			      (__u8 *)&host_mac.addr, ip4);
		if (ret != CTX_ACT_OK)
			return ret;

		return ctx_redirect(ctx, HOST_IFINDEX, 0);
	}
# endif
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
goog_geneve_pre_netdev_ingress_start(struct __ctx_buff *ctx)
{
	int ret = geneve_reset_state();
	__u32 flags = ctx_get_xfer(ctx, XFER_FLAGS);

	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	if (flags & XFER_PKT_GOOGLE_BPF_GENEVE) {
		if (geneve_set_current_bpf_program(
			    GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY) < 0)
			return DROP_WRITE_ERROR;
	} else {
		if (geneve_set_current_bpf_program(
			    GENEVE_BPF_PROGRAM_ID_FROM_NETDEV) < 0)
			return DROP_WRITE_ERROR;

		ret = geneve_try_decap4(ctx);
		if (ret != HOOK_ACT_CONTINUE)
			return ret;
	}

	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_host_ingress_start(void)
{
	int ret = geneve_reset_state();

	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	if (geneve_set_current_bpf_program(GENEVE_BPF_PROGRAM_ID_FROM_HOST) < 0)
		return DROP_WRITE_ERROR;

	return HOOK_ACT_CONTINUE;
}

#else /* ENABLE_GOOGLE_GENEVE */

/*
 * When Google geneve is not enabled, this function is basicly doing
 * what the original ctx_redirect() is doing.
 */
static __always_inline int google_geneve_ctx_redirect(
	struct __ctx_buff *ctx __maybe_unused, int ifindex, const __u32 flags)
{
# if __ctx_is == __ctx_xdp
	if ((__u32)ifindex == ctx->ingress_ifindex)
		return XDP_TX;
# endif
	return redirect(ifindex, flags);
}

static __always_inline int geneve_reset_state(void)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_ctr_egress_start4(void)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
geneve_redirect_to_overlay_if_encapped(struct __ctx_buff *ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_netdev_ingress_fwd4(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_netdev_ingress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_host_ingress_fwd4(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_host_ingress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
goog_geneve_pre_netdev_ingress_start(struct __ctx_buff *ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_host_ingress_start(void)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_netdev_ingress_fwd4_ipsec(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_host_ingress_fwd4_ctx_common *stage_ctx_common __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif /* ENABLE_GOOGLE_GENEVE */
