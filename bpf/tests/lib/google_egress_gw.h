static __always_inline void
add_egressgw_timeout_entry(__be32 saddr, __be32 daddr, __u8 cidr,
			   struct connection_timeouts ct_timeouts)
{
	struct egress_gw_policy_key in_key = {
		.lpm_key = { EGRESS_PREFIX_LEN(cidr), {} },
		.saddr = saddr,
		.daddr = daddr,
	};

	struct egress_gw_timeouts_entry in_val = {
		.egress_connection_timeouts = ct_timeouts,
	};

	map_update_elem(&EGRESS_POLICY_TIMEOUTS_MAP, &in_key, &in_val, 0);
}
