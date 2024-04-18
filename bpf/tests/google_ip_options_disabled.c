#include "common.h"
#include "bpf/ctx/skb.h"
#include "pktgen.h"

#define DEBUG

#include "lib/google_ip_options.h"

/* Test that extract_trace_id returns TRACE_ID_DISABLED when the feature is not
 * enabled by the proper compile flag.
 */
PKTGEN("tc", "extract_trace_id_disabled")
int test_extract_trace_id_disabled_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;

	pktgen__init(&builder, ctx);

	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;

	if (!pktgen__push_default_iphdr(&builder))
		return TEST_ERROR;

	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;

	pktgen__finish(&builder);

	return TEST_PASS;
}

CHECK("tc", "extract_trace_id_disabled")
int test_extract_trace_id_disabled_check(struct __ctx_buff *ctx)
{
	test_init();

	__s16 want = TRACE_ID_DISABLED;
	__s16 trace_id = trace_id_from_ctx(ctx);

	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}

	test_finish();
}
