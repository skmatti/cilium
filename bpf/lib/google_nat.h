#pragma once

#define EGRESS_STATIC_PREFIX (sizeof(__be32) * 8)
#define EGRESS_PREFIX_LEN(PREFIX) (EGRESS_STATIC_PREFIX + (PREFIX))
#define EGRESS_IPV4_PREFIX EGRESS_PREFIX_LEN(32)

#include "google_maps.h"

#ifndef GOOGLE_CLUSTER_ID
DEFINE_U32(GOOGLE_CLUSTER_ID, 0x10203040);
#define GOOGLE_CLUSTER_ID fetch_u32(GOOGLE_CLUSTER_ID)
#endif

static __always_inline int snat_v4_rewrite_egress_embedded(struct __ctx_buff *ctx,
							   struct ipv4_ct_tuple *tuple,
							   struct ipv4_nat_entry *state,
							   __u32 l4_off,
							   __u32 inner_l4_off)
{
	int ret, flags = BPF_F_PSEUDO_HDR;
	struct csum_offset csum = {};
	__be32 sum_l4 = 0, sum;

	if (state->to_saddr == tuple->saddr &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 4, &state->to_saddr, 4, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);

	if (state->to_sport != tuple->sport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, inner_l4_off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_sport,
					     tuple->sport);
			if (ret < 0)
				return ret;
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif /* ENABLE_SCTP */
		case IPPROTO_ICMP: {
			__be32 from, to;

			if (ctx_store_bytes(ctx,
					    inner_l4_off +
						offsetof(struct icmphdr, un.echo.id),
					    &state->to_sport,
					    sizeof(state->to_sport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->sport;
			to = state->to_sport;
			flags = 0; /* ICMPv4 has no pseudo-header */
			sum_l4 = csum_diff(&from, 4, &to, 4, 0);
			csum.offset = offsetof(struct icmphdr, checksum);
			break;
		}
		}
	}

	if (ctx_store_bytes(ctx, l4_off + sizeof(struct icmphdr) + offsetof(struct iphdr, daddr),
			    &state->to_saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(ctx, l4_off + sizeof(struct icmphdr) + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (tuple->nexthdr == IPPROTO_ICMP)
		sum = sum_l4;
	if (csum.offset &&
	    csum_l4_replace(ctx, inner_l4_off, &csum, 0, sum, flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline bool is_local_cluster_identity(__u32 seclabel)
{
	__u32 cluster_id = (seclabel >> 16) & ((1 << 8) - 1);
	/* Parse cluster_id from destination identity and check if equal to local cluster_id */
	if (cluster_id == GOOGLE_CLUSTER_ID)
		return true;
	return false;
}

#ifdef ENABLE_EGRESS_GATEWAY
static __always_inline
struct egress_gw_timeouts_entry *lookup_ip4_egress_timeout_entry(__be32 saddr, __be32 daddr)
{
	struct egress_gw_policy_key key = {
		.lpm_key = { EGRESS_IPV4_PREFIX, {} },
		.saddr = saddr,
		.daddr = daddr,
	};
	return map_lookup_elem(&EGRESS_POLICY_TIMEOUTS_MAP, &key);
}

static __always_inline void
lookup_egress_nat_timeouts(struct connection_timeouts **timeouts, __be32 saddr, __be32 daddr)
{
	struct egress_gw_timeouts_entry *egress_timeouts_entry = NULL;

	egress_timeouts_entry = lookup_ip4_egress_timeout_entry(saddr, daddr);

	if (egress_timeouts_entry)
		*timeouts = &egress_timeouts_entry->egress_connection_timeouts;
}
#else
static __always_inline
void lookup_egress_nat_timeouts(struct connection_timeouts **timeouts __maybe_unused,
				__be32 saddr __maybe_unused,
				__be32 daddr __maybe_unused)
{}
#endif /* ENABLE_EGRESS_GATEWAY */
