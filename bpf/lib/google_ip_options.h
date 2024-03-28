#ifndef __LIB_GOOGLE_IP_OPTIONS_H__
#define __LIB_GOOGLE_IP_OPTIONS_H__

#include "common.h"

/* IPv4 option used to carry trace id for a packet.
 *
 * Reuse deprecated stream ID option type for trace id.
 * A trace ID can be between 1 and 32,767.
 *
 * Example command for generating a traced packet with trace ID 99:
 *   `nping $IP --ip-options='\x88\x04\x00\x63'`
 *
 * [1]: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
 */
#define TRACE_IPV4_OPT_TYPE IPOPT_SID
#define TRACE_IPV4_OPT_LEN 4

/* The maximum number of IPv4 options to parse.
 *
 * When parsing IP options, we must cap the number of loops to ensure that the
 * loop is bounded, as per bpf requirement.
 *
 * 3 accounts for any combination of: trace ID, user-provided options, and
 * either egress NAT or DSR.
 */
#define MAX_IPV4_OPTS 3

/* The minimum value for IHL which corresponds to a packet with no options.
 *
 * A standard IP packet header has 20 bytes and the IHL is the number of 32 byte
 * words.
 */
#define IHL_WITH_NO_OPTS 5

// Signifies that options were parsed correctly but no trace ID was found.
#define TRACE_ID_NOT_FOUND 0

// Signifies a failure to determine the trace ID based on an unspecified error.
#define TRACE_ID_ERROR -1

// Signifies that the trace ID was found but it was invalid
#define TRACE_ID_INVALID -2

/* Signifies a failure to determine trace ID because the IP family was not found. */
#define TRACE_ID_NO_FAMILY -3

/* Signifies that the TRACE_ID was never parsed.
 *
 * This should be used for initialization instead of 0, so that it is clear when
 * a datapath has erroneously tried to emit an event without attempting to parse
 * the trace ID from a packet.
 */
#define TRACE_ID_UNSET -4

/* Signifies trace points which are being ignored because they're in IPv6
 * code and not supported yet.
 */
#define TRACE_ID_SKIP_IPV6 -100

// Signifies that the trace ID feature is disabled.
#define TRACE_ID_DISABLED -101

// Enable using "enable-ip-option-tracing: true".
#ifdef ENABLE_GOOGLE_IP_OPTION_TRACING

/* trace_id_from_ip4 parses the IP options and returns the trace ID.
 *
 * See trace_id_from_ctx for more info.
 */
static __always_inline __s16 trace_id_from_ip4(struct __ctx_buff *ctx, struct iphdr* ip4)
{
	__u32 offset;
	__u32 end;
	int i;
	__u8 opt_type;
	__u8 opt_len;
	__s16 trace_id;

	// Return immediately when there are no options in the header.
	if (ip4->ihl <= IHL_WITH_NO_OPTS) {
		return TRACE_ID_NOT_FOUND;
	}

	offset = ETH_HLEN + sizeof(struct iphdr);
	end = offset + (ip4->ihl << 2);

#pragma unroll(MAX_IPV4_OPTS)
	for (i = 0; i < MAX_IPV4_OPTS && offset < end; i++) {
		/* We load the option header 1 field at a time since different types
		 * have different formats.
		 *
		 * "Options 0 and 1 are exactly one octet which is their type field. All
		 * other options have their one octet type field, followed by a one
		 * octet length field, followed by length-2 octets of option data."
		 *
		 * Ref: https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
		 */

		if (ctx_load_bytes(ctx, offset, &opt_type, 1) < 0) {
			return TRACE_ID_ERROR;
		}
		if (opt_type == IPOPT_END) {
			break;
		}
		if (opt_type == IPOPT_NOOP) {
			offset++;
			continue;
		}

		if (ctx_load_bytes(ctx, offset+1, &opt_len, 1) < 0) {
			return TRACE_ID_ERROR;
		}
		if (opt_type != TRACE_IPV4_OPT_TYPE) {
			// The length field represents the entire option length (including
			// the type and length fields).
			offset += opt_len;
			continue;
		}
		if (opt_len != TRACE_IPV4_OPT_LEN) {
			return TRACE_ID_INVALID;
		}

		if (ctx_load_bytes(ctx, offset+2, &trace_id, sizeof(trace_id)) < 0) {
			return TRACE_ID_ERROR;
		}
		trace_id = bpf_ntohs(trace_id);

		// Non-positive numbers are used to indicate error, missing or invalid
		// trace ID.
		if (trace_id <= 0) {
			return TRACE_ID_INVALID;
		}

		return trace_id;
	}

	return TRACE_ID_NOT_FOUND;
}

/* trace_id_from_ctx parses the packet in the ctx and returns the trace ID.
 *
 * This function parses the packet buffer from scratch and is relatively
 * inefficient. Prefer to use trace_id_from_ip4 where possible for efficiency.
 *
 * A valid trace ID is a positive integer in the range 1-32,767 (inclusive).
 *
 * - When the packet has a valid trace ID, it returns a positive integer.
 * - When the packet does not have a trace ID, it returns 0.
 * - When parsing the options fails, it returns negative.
 * - When the trace ID is not in the correct range, it returns negative.
 */
static __always_inline __s16 trace_id_from_ctx(struct __ctx_buff *ctx)
{
	__u16 proto;
	void *data, *data_end;
	struct iphdr *ip4;

	if (!validate_ethertype(ctx, &proto)) {
		return TRACE_ID_ERROR;
	}
	if (proto == bpf_htons(ETH_P_IPV6)) {
		return TRACE_ID_SKIP_IPV6;
	}
	if (proto != bpf_htons(ETH_P_IP)) {
		return TRACE_ID_NO_FAMILY;
	}
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		return TRACE_ID_ERROR;
	}

	return trace_id_from_ip4(ctx, ip4);
}

#else

/*
 * Disable the feature by replacing all the funcs with ones that simply return
 * TRACE_ID_DISABLED.
 */

static __always_inline __s16 trace_id_from_ip4(struct __ctx_buff *ctx __maybe_unused, struct iphdr* ip4 __maybe_unused)
{
	return TRACE_ID_DISABLED;
}

static __always_inline __s16 trace_id_from_ctx(struct __ctx_buff *ctx __maybe_unused)
{
	return TRACE_ID_DISABLED;
}

#endif /* ENABLE_GOOGLE_IP_OPTION_TRACING */
#endif /* __LIB_GOOGLE_IP_OPTIONS_H__ */
