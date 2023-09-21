#ifndef __LIB_GOOGLE_NAT__
#define __LIB_GOOGLE_NAT__

static __always_inline int snat_v4_rewrite_egress_embedded(struct __ctx_buff *ctx,
						  struct ipv4_ct_tuple *tuple,
						  struct ipv4_nat_entry *state,
						  __u32 l4_off, __u32 inner_l4_off)
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
			ret = l4_modify_port(
			    ctx, inner_l4_off, offsetof(struct tcphdr, dest),
			    &csum, state->to_sport, tuple->sport);
			if (ret < 0)
				return ret;
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif /* ENABLE_SCTP */
		case IPPROTO_ICMP: {
			__be32 from, to;

			if (ctx_store_bytes(
				ctx,
				inner_l4_off +
				    offsetof(struct icmphdr, un.echo.id),
				&state->to_sport, sizeof(state->to_sport),
				0) < 0)
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

#endif  // __LIB_GOOGLE_NAT__
