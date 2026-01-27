#include "common.h"
#include <bpf/ctx/xdp.h>
#include "lib/google/xdp.h"

#define ENABLE_GOOGLE_GENEVE
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_DSR
#define DSR_ENCAP_IPIP 2
#define DSR_ENCAP_GENEVE 3
#define DSR_ENCAP_MODE DSR_ENCAP_GENEVE
#define DSR_ENCAP_NONE 1
#define SECLABEL 2222
#define ENCAP_IFINDEX 4

#define ENABLE_GOOGLE_IP_OPTION_TRACING

#include "node_config.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/tunnel.h"
#include "lib/google/ip_options.h"
#include "lib/google/geneve.h"
#include "tests/lib/google/pktgen.h"

/* Test google_ctx_load_bytes in XDP context.
 */
PKTGEN("xdp", "google_ctx_load_bytes")
int test_google_ctx_load_bytes_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	struct ethhdr *eth = pktgen__push_ethhdr(&builder);
	if (!eth) return DROP_INVALID;

	// Push some known data pattern
	// 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	__u8 payload[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	if (pktgen__push_data(&builder, payload, sizeof(payload)) == NULL)
		return DROP_INVALID;

	pktgen__finish(&builder);
	return 0;
}

/* Test google_ctx_load_bytes with arbitrary length in XDP.
 */
PKTGEN("xdp", "google_ctx_load_bytes_arbitrary")
int test_google_ctx_load_bytes_arbitrary_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	__u8 payload[64];
	int i;

	pktgen__init(&builder, ctx);

	if (!pktgen__push_ethhdr(&builder)) return DROP_INVALID;

	for (i = 0; i < 64; i++) {
		payload[i] = (__u8)i;
	}

	if (pktgen__push_data(&builder, payload, sizeof(payload)) == NULL)
		return DROP_INVALID;

	pktgen__finish(&builder);
	return 0;
}

CHECK("xdp", "google_ctx_load_bytes")
int test_google_ctx_load_bytes_check(struct __ctx_buff *ctx)
{
	test_init();

	// Skip ETH header (14 bytes)
	__u32 offset = sizeof(struct ethhdr);
	__u8 u8_val;
	__u16 u16_val;
	__u32 u32_val;
	__u8 buf[3];
	int ret;

	// Test 1: Read 1 byte
	// Expect 0x01 at offset 0
	ret = google_ctx_load_bytes(ctx, offset, &u8_val, 1);
	if (ret < 0) test_fatal("read 1 byte failed");
	if (u8_val != 0x01) test_fatal("read 1 byte mismatch: %x want 0x01", u8_val);

	// Test 2: Read 2 bytes
	// Expect 0x02 0x03 at offset 1 -> 0x0203
	ret = google_ctx_load_bytes(ctx, offset + 1, &u16_val, 2);
	if (ret < 0) test_fatal("read 2 bytes failed");
	// Verify byte by byte to be endian safe if needed, or just check value if we know host is LE.
	// The test runner usually runs on x86 (LE).
	// 0x02, 0x03 -> 0x0302
	if (u16_val != 0x0302) test_fatal("read 2 bytes mismatch: %x want 0x0302", u16_val);

	// Test 3: Read 4 bytes
	// Offset 3: 0x04, 0x05, 0x06, 0x07
	// LE: 0x07060504
	ret = google_ctx_load_bytes(ctx, offset + 3, &u32_val, 4);
	if (ret < 0) test_fatal("read 4 bytes failed");
	if (u32_val != 0x07060504) test_fatal("read 4 bytes mismatch: %x want 0x07060504", u32_val);

	// Test 4: Read 3 bytes
	// Offset 4: 0x05, 0x06, 0x07
	ret = google_ctx_load_bytes(ctx, offset + 4, buf, 3);
	if (ret < 0) test_fatal("read 3 bytes failed");
	if (buf[0] != 0x05 || buf[1] != 0x06 || buf[2] != 0x07)
		test_fatal("read 3 bytes mismatch: %x %x %x", buf[0], buf[1], buf[2]);

	// Test 5: Out of bounds
	// Payload is 8 bytes. ETH is 14. Total 22.
	// Try reading past 22.
	// Offset 22 is end. Reading 1 byte at 22 should fail.
	ret = google_ctx_load_bytes(ctx, offset + 8, &u8_val, 1);
	if (ret == 0) test_fatal("read OOB should fail but succeeded");

	test_finish();
}

CHECK("xdp", "google_ctx_load_bytes_arbitrary")
int test_google_ctx_load_bytes_arbitrary_check(struct __ctx_buff *ctx)
{
	test_init();

	__u32 offset = sizeof(struct ethhdr);
	__u8 buf[64];
	int ret, i;

	// Load 64 bytes at once
	ret = google_ctx_load_bytes(ctx, offset, buf, 64);
	if (ret < 0) test_fatal("read 64 bytes failed");

	for (i = 0; i < 64; i++) {
		if (buf[i] != (__u8)i)
			test_fatal("read mismatch at offset %d: got %x want %x", i, buf[i], i);
	}

	test_finish();
}
