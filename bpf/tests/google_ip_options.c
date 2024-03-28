#include "common.h"
#include "bpf/ctx/skb.h"
#include "pktgen.h"

#define DEBUG
#define ENABLE_GOOGLE_IP_OPTION_TRACING

#include "lib/google_ip_options.h"

// Used to define IP options for packet generation.
struct ip4opthdr {
	// type field of the IP option.
	__u8 type;
	// len field of the IP option. Usually equal to total length of the IP
	// option, including type and len. Can be specified different from data
	// length for testing purposes. If zero, it will not be written to the
	// packet, so that tests can specify single-byte options.
	__u8 len;
	// Arbitrary data for the payload of the IP option.
	__u8 *data;
	// Length of the data field in bytes. Must match exactly.
	__u8 data_len;
};

// Injects a packet into the ctx with the IPv4 options specified. See comments
// on the struct for more details on how to specify options. The total byte
// content of the options must align on 4-byte boundaries so that the IHL can be
// accurate.
//
// opts_len:   the number of options in opts.
// opts_bytes: the total number of bytes in options.
static __always_inline __maybe_unused int
gen_packet_with_options(struct __sk_buff *ctx, struct ip4opthdr *opts, __u8 opts_len, __u8 opts_bytes)
{
	struct pktgen builder;
	struct iphdr *l3;
	__u8 *new_opt;
	int i, j, new_opt_len;

	if (opts_bytes % 4 != 0)
		// Options must be aligned on 4-byte boundaries.
		return TEST_ERROR;

	pktgen__init(&builder, ctx);

	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;

	l3 = pktgen__push_default_iphdr_with_options(&builder, opts_bytes / 4);
	if (!l3)
		return TEST_ERROR;

	// opts start just after the l3 header.
	new_opt = (__u8*) &l3[1];
	for (i = 0; i < opts_len; i++) {
		new_opt_len = 0;

		new_opt[0] = opts[i].type;
		new_opt_len++;
		if (opts[i].len != 0) {
			new_opt[new_opt_len] = opts[i].len;
			new_opt_len++;
		}
		for (j = 0; j < opts[i].data_len; j++) {
			new_opt[new_opt_len] = opts[i].data[j];
			new_opt_len++;
		}
		new_opt += new_opt_len;
	}

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);

	return TEST_PASS;
}

/* Test a single option specifying the trace ID with no special cases.
 */
PKTGEN("tc", "extract_trace_id_solo")
int test_extract_trace_id_solo_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = TRACE_IPV4_OPT_TYPE,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 1, 4);
}

CHECK("tc", "extract_trace_id_solo")
int test_extract_trace_id_solo_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = 1;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test three options with the trace ID option being first.
 */
PKTGEN("tc", "extract_trace_id_first_of_three")
int test_extract_trace_id_first_of_three_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = TRACE_IPV4_OPT_TYPE,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = 10,
			.len = 4,
			.data = (__u8*)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8*)"\x11\x11",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 3, 12);
}

CHECK("tc", "extract_trace_id_first_of_three")
int test_extract_trace_id_first_of_three_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = 1;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test three options with the trace ID option being between the other two.
 */
PKTGEN("tc", "extract_trace_id_middle_of_three")
int test_extract_trace_id_middle_of_three_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 10,
			.len = 4,
			.data = (__u8*)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = TRACE_IPV4_OPT_TYPE,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8*)"\x11\x11",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 3, 12);
}

CHECK("tc", "extract_trace_id_middle_of_three")
int test_extract_trace_id_middle_of_three_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = 1;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test three options with the trace ID option being last of the three.
 */
PKTGEN("tc", "extract_trace_id_last_of_three")
int test_extract_trace_id_last_of_three_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 10,
			.len = 4,
			.data = (__u8*)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8*)"\x11\x11",
			.data_len = 2,
		},
		{
			.type = TRACE_IPV4_OPT_TYPE,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 3, 12);
}

CHECK("tc", "extract_trace_id_last_of_three")
int test_extract_trace_id_last_of_three_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = 1;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test two options with the trace ID coming after an unusually sized option.
 */
PKTGEN("tc", "extract_trace_id_after_other_option_with_diff_len")
int test_extract_trace_id_after_other_option_with_diff_len_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 11,
			.len = 12, // large option
			.data = (__u8*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.data_len = 10,
		},
		{
			.type = TRACE_IPV4_OPT_TYPE,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 2, 16);
}

CHECK("tc", "extract_trace_id_after_other_option_with_diff_len")
int test_extract_trace_id_after_other_option_with_diff_len_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = 1;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test multiple options with the trace ID coming after a NOOP option.
 */
PKTGEN("tc", "extract_trace_id_after_ipopt_noop")
int test_extract_trace_id_after_ipopt_noop_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = TRACE_IPV4_OPT_TYPE,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
	};

	return gen_packet_with_options(ctx, opts, 5, 8);
}

CHECK("tc", "extract_trace_id_after_ipopt_noop")
int test_extract_trace_id_after_ipopt_noop_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = 1;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test multiple options with the trace ID not present should return TRACE_ID_NOT_FOUND.
 */
PKTGEN("tc", "extract_trace_id_not_found_with_other_options")
int test_extract_trace_id__not_found_with_other_options_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 10,
			.len = 4,
			.data = (__u8*)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8*)"\x11\x11",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 2, 8);
}

CHECK("tc", "extract_trace_id_not_found_with_other_options")
int test_extract_trace_id_not_found_with_other_options_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = TRACE_ID_NOT_FOUND;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test no options present should return TRACE_ID_NOT_FOUND.
 */
PKTGEN("tc", "extract_trace_id_not_found_with_no_options")
int test_extract_trace_id_not_found_with_no_options_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {};

	return gen_packet_with_options(ctx, opts, 0, 0);
}

CHECK("tc", "extract_trace_id_not_found_with_no_options")
int test_extract_trace_id_not_found_with_no_options_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = TRACE_ID_NOT_FOUND;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test trace ID after END should return TRACE_ID_NOT_FOUND.
 */
PKTGEN("tc", "extract_trace_id_after_ipopt_end_not_found")
int test_extract_trace_id_after_ipopt_end_not_found_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = IPOPT_END,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = TRACE_IPV4_OPT_TYPE,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
		// Add padding to align on 4-byte boundary.
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
	};

	return gen_packet_with_options(ctx, opts, 5, 8);
}

CHECK("tc", "extract_trace_id_after_ipopt_end_not_found")
int test_extract_trace_id_after_ipopt_end_not_found_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = TRACE_ID_NOT_FOUND;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test trace ID comes after loop limit should return TRACE_ID_NOT_FOUND.
 */
PKTGEN("tc", "extract_trace_id_after_loop_limit_not_found")
int test_extract_trace_id_after_loop_limit_not_found_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		// The loop limit is 3 so the following options are ignored.
		{
			.type = TRACE_IPV4_OPT_TYPE,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
	};
	return gen_packet_with_options(ctx, opts, 5, 8);
}

CHECK("tc", "extract_trace_id_after_loop_limit_not_found")
int test_extract_trace_id_after_loop_limit_not_found_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = TRACE_ID_NOT_FOUND;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test trace ID with negative value should return TRACE_ID_INVALID.
 */
PKTGEN("tc", "extract_trace_id_negative_invalid")
int test_extract_trace_id_negative_invalid_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = TRACE_IPV4_OPT_TYPE,
			.len = 4,
			.data = (__u8*)"\x80\x01", // First bit makes it negative.
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 1, 4);
}

CHECK("tc", "extract_trace_id_negative_invalid")
int test_extract_trace_id_negative_invalid_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = TRACE_ID_INVALID;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test trace ID with incorrect length field should return INVALID.
 */
PKTGEN("tc", "extract_trace_id_wrong_len_invalid")
int test_extract_trace_id_wrong_len_invalid_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = TRACE_IPV4_OPT_TYPE,
			.len = 3, // Should be 4.
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
	};

	return gen_packet_with_options(ctx, opts, 1, 4);
}

CHECK("tc", "extract_trace_id_wrong_len_invalid")
int test_extract_trace_id_wrong_len_invalid_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = TRACE_ID_INVALID;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test packet with no l3 header should return TRACE_ID_ERROR.
 */
PKTGEN("tc", "extract_trace_id_with_no_l3_header_error")
int test_extract_trace_id_with_no_l3_header_error_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;

	// Missing L3 header.

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);

	return TEST_PASS;
}

CHECK("tc", "extract_trace_id_with_no_l3_header_error")
int test_extract_trace_id_with_no_l3_header_error_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = TRACE_ID_ERROR;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test packet with no eth header should return TRACE_ID_NO_FAMILY.
 */
PKTGEN("tc", "extract_trace_id_with_no_eth_header_no_family")
int test_extract_trace_id_with_no_eth_header_no_family_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	// Missing eth and l3 headers.

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);

	return TEST_PASS;
}

CHECK("tc", "extract_trace_id_with_no_eth_header_no_family")
int test_extract_trace_id_with_no_eth_header_no_family_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = TRACE_ID_NO_FAMILY;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}

/* Test packet with IPv6 header should return TRACE_ID_SKIP_IPV6.
 */
PKTGEN("tc", "extract_trace_id_with_ipv6_header_skip")
int test_extract_trace_id_with_ipv6_header_skip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;

	if (!pktgen__push_default_ipv6hdr(&builder))
		return TEST_ERROR;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);

	return TEST_PASS;
}

CHECK("tc", "extract_trace_id_with_ipv6_header_skip")
int test_extract_trace_id_with_ipv6_header_skip_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = TRACE_ID_SKIP_IPV6;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}
