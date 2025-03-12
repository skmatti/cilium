#define TAIL_CT_LOOKUP4_W_TIMEOUT(ID, NAME, DIR, CONDITION, TARGET_ID, TARGET_NAME) \
	__section_tail(CILIUM_MAP_CALLS, ID) static __always_inline int             \
	NAME(struct __ctx_buff *ctx)                                                \
	{                                                                           \
		struct connection_timeouts *connection_timeouts                     \
			__maybe_unused = NULL;                                      \
		struct ct_buffer4 ct_buffer = {};                                   \
		struct ipv4_ct_tuple *tuple;                                        \
		struct ct_state *ct_state;                                          \
		void *data, *data_end;                                              \
		int ret = CTX_ACT_OK;                                               \
		struct iphdr *ip4;                                                  \
		__s8 ext_err = 0;                                                   \
		__u32 zero = 0;                                                     \
		void *map;                                                          \
		ct_state = (struct ct_state *)&ct_buffer.ct_state;                  \
		tuple = (struct ipv4_ct_tuple *)&ct_buffer.tuple;                   \
		if (!revalidate_data(ctx, &data, &data_end, &ip4))                  \
			return drop_for_direction(                                  \
				ctx, DIR, DROP_INVALID, ext_err);                   \
		tuple->nexthdr = ip4->protocol;                                     \
		tuple->daddr = ip4->daddr;                                          \
		tuple->saddr = ip4->saddr;                                          \
		ct_buffer.l4_off = ETH_HLEN + ipv4_hdrlen(ip4);                     \
		map = select_ct_map4(ctx, DIR, tuple);                              \
		if (!map)                                                           \
			return drop_for_direction(                                  \
				ctx, DIR, DROP_CT_NO_MAP_FOUND, ext_err);           \
		lookup_egress_nat_timeouts(                                         \
			&connection_timeouts, tuple->daddr, tuple->saddr);          \
		ct_buffer.ret = ct_lookup4_w_timeouts(                              \
			map, tuple, ctx, ip4, ct_buffer.l4_off, DIR, ct_state,      \
			&ct_buffer.monitor, connection_timeouts);                   \
		if (ct_buffer.ret < 0)                                              \
			return drop_for_direction(                                  \
				ctx, DIR, ct_buffer.ret, ext_err);                  \
		if (map_update_elem(&CT_TAIL_CALL_BUFFER4, &zero, &ct_buffer, 0) <  \
		    0)                                                              \
			return drop_for_direction(                                  \
				ctx, DIR, DROP_INVALID_TC_BUFFER, ext_err);         \
		ret = invoke_tailcall_if(                                           \
			CONDITION, TARGET_ID, TARGET_NAME, &ext_err);               \
		if (IS_ERR(ret))                                                    \
			return drop_for_direction(ctx, DIR, ret, ext_err);          \
		return ret;                                                         \
	}
