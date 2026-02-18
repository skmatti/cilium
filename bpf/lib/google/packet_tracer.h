#pragma once

#include "hooks_common.h"
#include "lib/lb.h"
#include "lib/identity.h"
#include "ip_options.h"

/* Defines max entries for google_traffic_tag_map. */
#define GOOGLE_TRAFFIC_TAG_MAP_MAX_ENTRIES 1024

struct trace_opt_v4 {
	__u8 type;
	__u8 len;
	__u16 trace_id;
};

struct google_traffic_tag_key {
	__be32 source_ip;
	__be32 dest_ip;
	__be16 dest_port;
	__be16 src_port;
	__u8   protocol;
	/* Pad to 16 bytes to meet the BPF map key size requirement for efficiency. */
	__u8   pad[3];
} __packed;

struct google_traffic_tag_value {
	__u16 trace_id;
} __packed;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct google_traffic_tag_key);
	__type(value, struct google_traffic_tag_value);
	__uint(max_entries, GOOGLE_TRAFFIC_TAG_MAP_MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} google_traffic_tag_map __section_maps_btf;

/* Enable using "enable-ip-option-tracing: true". */
#ifdef ENABLE_GOOGLE_IP_OPTION_TRACING

/* Function to inject the IP option with Type = TRACE_IPV4_OPT_TYPE */
static __always_inline int add_trace_ip_opt_v4(struct __ctx_buff *ctx, struct iphdr *iph, __u16 trace_id) {
	struct trace_opt_v4 ip_option;
	__u32 iph_old, iph_new;
	__u32 sum_l3;
	int ip_header_len = iph->ihl << 2;

	/* Calculate the total header length (Ethernet + IP) */
	int total_header_len = ETH_HLEN + ip_header_len;

	/* Construct the IP option with the trace_id */
	ip_option.type = TRACE_IPV4_OPT_TYPE; /* Option type */
	ip_option.len = TRACE_IPV4_OPT_LEN; /* Option length */
	ip_option.trace_id = bpf_htons(trace_id); /* trace_id */


	/* Update the IP header length */
	iph_old = *(__u32 *)iph;
	iph->ihl += TRACE_IPV4_OPT_LEN >> 2;
	iph->tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + TRACE_IPV4_OPT_LEN);
	iph_new = *(__u32 *)iph;

	sum_l3 = csum_diff(&iph_old, TRACE_IPV4_OPT_LEN, &iph_new, TRACE_IPV4_OPT_LEN, 0);
	sum_l3 = csum_diff(NULL, 0, &ip_option, sizeof(ip_option), sum_l3);

	/* 1. Increase headroom */
	if (ctx_adjust_hroom(ctx, TRACE_IPV4_OPT_LEN, BPF_ADJ_ROOM_NET, 0))
		return DROP_INVALID; /* Error increasing headroom */

	/* 2. Copy IP options */
	if (ctx_store_bytes(ctx, total_header_len, &ip_option, sizeof(ip_option), 0) < 0)
		return DROP_INVALID; /* Error copying IP Options */

	/* 3. Replace the IP checksum */
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check), 0, sum_l3, 0) < 0)
		return DROP_CSUM_L3; /* Failed to recalculate checksum */

	return 0;
}

/* TODO(b/430208938): Profile find_trace_id_from_map_v4 with best and worst case. */
static __always_inline __u16 find_trace_id_from_map_v4(struct __ctx_buff *ctx __maybe_unused, struct iphdr *ip __maybe_unused) {
#ifdef ENABLE_IPV4
	struct google_traffic_tag_key key = {};
	struct google_traffic_tag_value *value;
	int err, l4_off = 0;
	struct ipv4_ct_tuple tuple = {};
	__u8 protocol;
	/* Extract the tuple from the packet so we can freely access addrs and ports.
	* All values are in network byte order.
	*/
	err = lb4_extract_tuple(ctx, ip, ETH_HLEN, &l4_off, &tuple);
	if (IS_ERR(err)) {
		return 0;
	}
	/* CT expects a tuple with the source and destination ports reversed,
	* while Packet tracing uses normal tuples that match packet headers.
	*/
	ipv4_ct_tuple_swap_ports(&tuple);

	protocol = tuple.nexthdr;

	/*
	* The following code implements a fallback mechanism to find a matching
	* entry in the google_traffic_tag_map.
	*
	* Order for matching key is as below:
	* key: <source_ip, dest_ip, dest_port, source_port, protocol>
	*
	* 1: <source_ip, dest_ip, dest_port, source_port, protocol>
	* 2: <source_ip, dest_ip, dest_port, source_port, 0       >
	* 3: <source_ip, dest_ip, dest_port, 0          , protocol>
	* 4: <source_ip, dest_ip, 0        , source_port, protocol>
	* 5: <source_ip, dest_ip, dest_port, 0          , 0       >
	* 6: <source_ip, dest_ip, 0        , source_port, 0       >
	* 7: <source_ip, dest_ip, 0        , 0          , protocol>
	* 8: <source_ip, 0      , 0        , source_port, protocol>
	* 9: <0        , dest_ip, dest_port, 0          , protocol>
	* 10: <source_ip, dest_ip, 0        , 0          , 0       >
	* 11: <source_ip, 0      , 0        , source_port, 0       >
	* 12: <source_ip, 0      , 0        , 0          , protocol>
	* 13: <0        , dest_ip, dest_port, 0          , 0       >
	* 14: <0        , dest_ip, 0        , 0          , protocol>
	* 15: <source_ip, 0      , 0        , 0          , 0       >
	* 16: <0        , dest_ip, 0        , 0          , 0       >
	*/

	/* 1: <source_ip, dest_ip, dest_port, source_port, protocol> */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = tuple.daddr,
		.dest_port = bpf_ntohs(tuple.dport),
		.src_port = bpf_ntohs(tuple.sport),
		.protocol = protocol,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 2: <source_ip, dest_ip, dest_port, source_port, 0       > */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = tuple.daddr,
		.dest_port = bpf_ntohs(tuple.dport),
		.src_port = bpf_ntohs(tuple.sport),
		.protocol = 0,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 3: <source_ip, dest_ip, dest_port, 0          , protocol> */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = tuple.daddr,
		.dest_port = bpf_ntohs(tuple.dport),
		.src_port = 0,
		.protocol = protocol,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 4: <source_ip, dest_ip, 0        , source_port, protocol> */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = tuple.daddr,
		.dest_port = 0,
		.src_port = bpf_ntohs(tuple.sport),
		.protocol = protocol,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 5: <source_ip, dest_ip, dest_port, 0          , 0       > */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = tuple.daddr,
		.dest_port = bpf_ntohs(tuple.dport),
		.src_port = 0,
		.protocol = 0,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 6: <source_ip, dest_ip, 0        , source_port, 0       > */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = tuple.daddr,
		.dest_port = 0,
		.src_port = bpf_ntohs(tuple.sport),
		.protocol = 0,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 7: <source_ip, dest_ip, 0        , 0          , protocol> */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = tuple.daddr,
		.dest_port = 0,
		.src_port = 0,
		.protocol = protocol,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 8: <source_ip, 0      , 0        , source_port, protocol> */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = 0,
		.dest_port = 0,
		.src_port = bpf_ntohs(tuple.sport),
		.protocol = protocol,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 9: <0        , dest_ip, dest_port, 0          , protocol> */
	key = (struct google_traffic_tag_key){
		.source_ip = 0,
		.dest_ip = tuple.daddr,
		.dest_port = bpf_ntohs(tuple.dport),
		.src_port = 0,
		.protocol = protocol,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 10: <source_ip, dest_ip, 0        , 0          , 0       > */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = tuple.daddr,
		.dest_port = 0,
		.src_port = 0,
		.protocol = 0,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 11: <source_ip, 0      , 0        , source_port, 0       > */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = 0,
		.dest_port = 0,
		.src_port = bpf_ntohs(tuple.sport),
		.protocol = 0,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 12: <source_ip, 0      , 0        , 0          , protocol> */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = 0,
		.dest_port = 0,
		.src_port = 0,
		.protocol = protocol,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 13: <0        , dest_ip, dest_port, 0          , 0       > */
	key = (struct google_traffic_tag_key){
		.source_ip = 0,
		.dest_ip = tuple.daddr,
		.dest_port = bpf_ntohs(tuple.dport),
		.src_port = 0,
		.protocol = 0,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 14: <0        , dest_ip, 0        , 0          , protocol> */
	key = (struct google_traffic_tag_key){
		.source_ip = 0,
		.dest_ip = tuple.daddr,
		.dest_port = 0,
		.src_port = 0,
		.protocol = protocol,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 15: <source_ip, 0      , 0        , 0          , 0       > */
	key = (struct google_traffic_tag_key){
		.source_ip = tuple.saddr,
		.dest_ip = 0,
		.dest_port = 0,
		.src_port = 0,
		.protocol = 0,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	/* 16: <0        , dest_ip, 0        , 0          , 0       > */
	key = (struct google_traffic_tag_key){
		.source_ip = 0,
		.dest_ip = tuple.daddr,
		.dest_port = 0,
		.src_port = 0,
		.protocol = 0,
	};
	value = map_lookup_elem(&google_traffic_tag_map, &key);
	if (value) {
		return value->trace_id;
	}

	#endif /* ENABLE_IPV4 */
	return 0;
}

/*
 * __process_ipv4_option_iteration
 *
 * Processes a single iteration of IPv4 option parsing. This function is intended
 * to be called within a loop that iterates through IP options.
 *
 * @ctx: The socket buffer context.
 * @current_offset_ptr: Pointer to the current offset within the IP options.
 *                      This value will be updated by the function.
 * @options_end: The offset marking the end of the IP options section.
 * @option_to_remove_offset_ptr: Pointer to store the offset of the TRACE_IPV4_OPT_TYPE
 *                               option if found.
 * @option_to_remove_len_ptr: Pointer to store the length of the TRACE_IPV4_OPT_TYPE
 *                            option if found.
 * @keep_processing_ptr: Pointer to a boolean flag. Set to false if processing
 *                       should stop (e.g., IPOPT_END or target option found).
 * Returns:
 *  - 0 on successful processing of the current option.
 *  - TRACE_ID_ERROR if there's an error reading option data or if options are malformed.
 *  - TRACE_ID_INVALID if TRACE_IPV4_OPT_TYPE is found with an incorrect length.
 */
static __always_inline int __process_ipv4_option_iteration(
	struct __ctx_buff *ctx,
	__u32 *current_offset_ptr,
	__u32 options_end,
	__u32 *option_to_remove_offset_ptr,
	__u8 *option_to_remove_len_ptr,
	bool *keep_processing_ptr)
{
	__u8 opt_type_loop;
	__u8 opt_len_loop;
	__u32 current_offset = *current_offset_ptr;

	if (ctx_load_bytes(ctx, current_offset, &opt_type_loop, 1) < 0)
		return TRACE_ID_ERROR;

	if (opt_type_loop == IPOPT_END) {
		*keep_processing_ptr = false;
	} else if (opt_type_loop == IPOPT_NOOP) {
		current_offset++;
	} else {
		if (current_offset + 1 >= options_end)
			return TRACE_ID_ERROR;
		if (ctx_load_bytes(ctx, current_offset + 1, &opt_len_loop, 1) < 0)
			return TRACE_ID_ERROR;
		if (opt_len_loop < 2)
			return TRACE_ID_ERROR;
		if (current_offset + opt_len_loop > options_end)
			return TRACE_ID_ERROR;

		if (opt_type_loop == TRACE_IPV4_OPT_TYPE) {
			if (opt_len_loop != TRACE_IPV4_OPT_LEN)
				return TRACE_ID_INVALID;
			*option_to_remove_offset_ptr = current_offset;
			*option_to_remove_len_ptr = opt_len_loop;
			*keep_processing_ptr = false;
		} else {
			current_offset += opt_len_loop;
		}
	}
	*current_offset_ptr = current_offset;
	return 0;
}

/*
 * remove_trace_ip_opt_v4
 *
 * Removes the Google Flow Tagger IP option (TRACE_IPV4_OPT_TYPE) from an IPv4 packet.
 *
 * @ctx: The socket buffer context.
 * Returns:
 *  - The length of the removed option (e.g., TRACE_IPV4_OPT_LEN) on success.
 *  - 0 if the option was not found or if the packet is not IPv4/has no options.
 *  - A negative error code on failure (e.g., packet malformed, skb adjustment error).
 */
static __always_inline int remove_trace_ip_opt_v4(struct __ctx_buff *ctx)
{
	void *data_start, *data_end;
	struct iphdr *iph;
	const struct ethhdr *eth;
	__u32 current_offset;
	__u32 options_end;
	int i;
	__u32 option_to_remove_offset = 0;
	__u8 option_to_remove_len = 0;
	bool keep_processing = true;
	int process_ret = 0;
	struct trace_opt_v4 opt_to_remove_data, noop_replacement_data;
	__u32 csum_l3;

	if (!revalidate_data(ctx, &data_start, &data_end, &iph))
		return DROP_INVALID;

	eth = data_start;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TRACE_ID_NOT_FOUND; /* Not an IPv4 packet */

	if (iph->version != 4)
		return TRACE_ID_NOT_FOUND; /* Not IPv4 */

	/* Return immediately when there are no options in the header. */
	if (iph->ihl <= IHL_WITH_NO_OPTS)
		return TRACE_ID_NOT_FOUND; /* No options to remove */

	current_offset = ETH_HLEN + sizeof(struct iphdr);
	options_end = ETH_HLEN + (iph->ihl << 2);

	/* Ensure the calculated options_end is within packet bounds */
	if (data_start + options_end > data_end)
		return TRACE_ID_ERROR; /* IP header length (IHL) is incorrect / exceeds packet data */

#pragma unroll(MAX_IPV4_OPTS)
	for (i = 0; i < MAX_IPV4_OPTS; i++) {
		if (keep_processing && current_offset < options_end) {
			process_ret = __process_ipv4_option_iteration(ctx, &current_offset,
								      options_end,
								      &option_to_remove_offset,
								      &option_to_remove_len,
								      &keep_processing);
			if (process_ret != 0) {
				return process_ret;
			}
		}
	}

	/* Option not found */
	if (option_to_remove_offset == 0) {
		return TRACE_ID_NOT_FOUND;
	}

	/* Load the actual option data for checksum calculation */
	if (ctx_load_bytes(ctx, option_to_remove_offset, &opt_to_remove_data, sizeof(opt_to_remove_data)) < 0)
		return DROP_INVALID;

	/* Ensure the loaded length matches the expected length for safety */
	if (opt_to_remove_data.len != TRACE_IPV4_OPT_LEN || option_to_remove_len != TRACE_IPV4_OPT_LEN) {
		return TRACE_ID_INVALID; /* Should not happen if logic above is correct */
	}

	memset(&noop_replacement_data, IPOPT_NOOP, sizeof(struct trace_opt_v4));

	/* Calculate checksum difference for replacing option with NOOPs */
	csum_l3 = csum_diff(&opt_to_remove_data, sizeof(opt_to_remove_data),
				   &noop_replacement_data, sizeof(noop_replacement_data), 0);

	/* Store NOOPs over the found option */
	if (ctx_store_bytes(ctx, option_to_remove_offset, &noop_replacement_data, sizeof(noop_replacement_data), 0) < 0)
		return DROP_WRITE_ERROR;

	/* Update the IP header checksum */
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check), 0, csum_l3, 0) < 0)
		return DROP_CSUM_L3;

	return option_to_remove_len; /* Return the length of the option that was "removed" (nulled) */
}

static __always_inline int check_and_add_trace_ip_opt(struct __ctx_buff *ctx)
{
	__u16 proto = 0;
	validate_ethertype(ctx, &proto);
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		{
			void *data, *data_end;
			struct iphdr *ip4;

			if (!revalidate_data(ctx, &data, &data_end, &ip4))
				return DROP_INVALID;

			if (!trace_id_from_ip4(ctx, ip4->ihl)) {
				__u16 trace_id = find_trace_id_from_map_v4(ctx, ip4);
				if (trace_id != 0) {
					int err = add_trace_ip_opt_v4(ctx, ip4, trace_id);
					if (IS_ERR(err))
						return err;
				}
			}
		}
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		break;
#endif /* ENABLE_IPV6 */
	default:
		break;
	}
	return CTX_ACT_OK;
}

static __always_inline int check_and_remove_trace_ip_opt(struct __ctx_buff *ctx)
{
	__u16 proto = 0;
	validate_ethertype(ctx, &proto);
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		{
			void *data, *data_end;
			struct iphdr *ip4;
			int err;
			if (!revalidate_data(ctx, &data, &data_end, &ip4))
				return DROP_INVALID;

			err = remove_trace_ip_opt_v4(ctx);
			if (IS_ERR(err))
				return err;
		}
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		break;
#endif /* ENABLE_IPV6 */
	default:
		break;
	}
	return CTX_ACT_OK;
}

static __always_inline int check_and_add_trace_ip_opt_post_dnat(struct __ctx_buff *ctx){
	return check_and_add_trace_ip_opt(ctx);
}
#ifdef ENABLE_GOOGLE_NORTH_SOUTH_IP_OPTION_TRACING
/*
 * check_and_remove_trace_ip_opt_ns is a convinent function call for removing trace ip-option header
 * for North-South traffic.
 * removal only take place if the destination is not a part of the clustermesh.
 */
static __always_inline int check_and_remove_trace_ip_opt_ns(struct __ctx_buff *ctx)
{
	__u16 proto = 0;
	validate_ethertype(ctx, &proto);
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		{
			void *data, *data_end;
			struct iphdr *ip4;
			struct remote_endpoint_info *info;
			unsigned int dst_id = 0;
			if (!revalidate_data(ctx, &data, &data_end, &ip4))
				return DROP_INVALID;

			info = lookup_ip4_remote_endpoint(ip4->daddr, 0);
			if (info == NULL) {
				dst_id = WORLD_ID;
			} else {
				dst_id = info->sec_identity;
			}

			/* destination should not be inside cluster */
			if (!identity_is_cluster(dst_id)) {
				int err = remove_trace_ip_opt_v4(ctx);
				if (IS_ERR(err))
					return err;
			}
		}
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		break;
#endif /* ENABLE_IPV6 */
	default:
		break;
	}
	return CTX_ACT_OK;
}

/*
 * add_trace_ip_opt_ns is a convenient function call for adding the trace ip-option header
 * for North-South traffic.
 * Addition only takes place if the source is not part of the clustermesh and if the tag is
 * not already present and there exist a key in the eBPF google_traffic_tag_map for the
 * current packet.
 */
static __always_inline int check_and_add_trace_ip_opt_ns(struct __ctx_buff *ctx)
{
	__u16 proto = 0;
	validate_ethertype(ctx, &proto);
	switch (proto) {
#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		{
			__u16 trace_id = 0;
			void *data, *data_end;
			struct iphdr *ip4;
			struct remote_endpoint_info *info;
			unsigned int src_id = 0;
			if(!revalidate_data(ctx, &data, &data_end, &ip4)) {
				return DROP_INVALID;
			}

			info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
			if (info == NULL) {
				src_id = WORLD_ID;
			} else {
				src_id = info->sec_identity;
			}
			/* source should not be inside cluster */
			if (!identity_is_cluster(src_id)) {
				trace_id = find_trace_id_from_map_v4(ctx, ip4);
				/* only tag the packet if there is an entry for it in google_traffic_tag_map */
				/* and ip-options header is absent from the packet */
				if (trace_id != 0 && !trace_id_from_ip4(ctx, ip4->ihl)) {
					int err = add_trace_ip_opt_v4(ctx, ip4, trace_id);
					if (IS_ERR(err))
						return err;
				}
			}
		}
		break;
#endif /* ENABLE_IPV4 */
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		break;
#endif /* ENABLE_IPV6 */
	default:
		break;
	}
	return CTX_ACT_OK;
}

static __always_inline int check_and_add_trace_ip_opt_post_snat(struct __ctx_buff *ctx __maybe_unused){
	return CTX_ACT_OK;
}
#else
static __always_inline int check_and_remove_trace_ip_opt_ns(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline int check_and_add_trace_ip_opt_ns(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline int check_and_add_trace_ip_opt_post_snat(struct __ctx_buff *ctx){
	return check_and_add_trace_ip_opt(ctx);
}
#endif /* ENABLE_GOOGLE_NORTH_SOUTH_IP_OPTION_TRACING */

#ifdef IS_BPF_LXC
/**
 * goog_ctr_egress_add_trace_ip_option_v4 - add ip-options header to the container's egress packet.
 */
static __always_inline int
goog_ctr_egress_add_trace_ip_option_v4(struct __ctx_buff *ctx)
{
	int ret = check_and_add_trace_ip_opt(ctx);
	if (IS_ERR(ret))
		return ret;

	return HOOK_ACT_CONTINUE;
}

/**
 * goog_ctr_egress_pol4_add_trace_ip_option_v4 - add ip-options header to the container's egress packet
 * after DNAT, to handle case where a packet can match some key in google_traffic_tag_map eBPF map
 */
static __always_inline int
goog_ctr_egress_pol4_add_trace_ip_option_v4(struct __ctx_buff *ctx)
{
	int ret = check_and_add_trace_ip_opt(ctx);
	if (IS_ERR(ret))
		return ret;

	return HOOK_ACT_CONTINUE;
}

/**
 * goog_ctr_ingress_remove_trace_ip_option_v4 - remove ip-options header from the container's ingress packet.
 */
static __always_inline int
goog_ctr_ingress_remove_trace_ip_option_v4(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	if (LXC_IPV4 == ip4->daddr) {
		int err = remove_trace_ip_opt_v4(ctx);
		if (IS_ERR(err))
			return err;
	}
	return HOOK_ACT_CONTINUE;
}
#endif /* IS_BPF_LXC */
#ifdef IS_BPF_HOST
/**
 * goog_netdev_ingress_add_trace_ip_option_ns_v4 - add ip-options tag for the south bound traffic.
 */
static __always_inline int
goog_netdev_ingress_add_trace_ip_option_ns_v4(struct __ctx_buff *ctx)
{
	int err = check_and_add_trace_ip_opt_ns(ctx);
	if (IS_ERR(err))
		return err;

	return HOOK_ACT_CONTINUE;
}
#endif /* IS_BPF_HOST */
#else
/*
 * Disable the feature by replacing all the funcs with ones that simply return
 * TRACE_ID_DISABLED.
 */

static __always_inline int check_and_remove_trace_ip_opt_ns(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline int check_and_add_trace_ip_opt_ns(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline int check_and_add_trace_ip_opt_post_dnat(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline int check_and_add_trace_ip_opt_post_snat(struct __ctx_buff *ctx __maybe_unused)
{
	return CTX_ACT_OK;
}
#ifdef IS_BPF_LXC
static __always_inline int
goog_ctr_egress_add_trace_ip_option_v4(struct __ctx_buff *ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
goog_ctr_egress_pol4_add_trace_ip_option_v4(struct __ctx_buff *ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
goog_ctr_ingress_remove_trace_ip_option_v4(struct __ctx_buff *ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}
#endif /* IS_BPF_LXC */
#ifdef IS_BPF_HOST
static __always_inline int
goog_netdev_ingress_add_trace_ip_option_ns_v4(struct __ctx_buff *ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}
#endif /* IS_BPF_HOST */
#endif /* ENABLE_GOOGLE_IP_OPTION_TRACING */
