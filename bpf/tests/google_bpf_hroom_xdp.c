#include "common.h"
#include <bpf/ctx/xdp.h>
#include "lib/google/xdp.h"
#include <linux/if_ether.h>
#include <bpf/helpers_xdp.h>

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

#include "node_config.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/tunnel.h"

#include "lib/google/geneve.h"
#include "tests/lib/google/pktgen.h"

#include "lib/google/xdp.h"

PKTGEN("xdp", "shrink")
int test_shrink_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	struct ethhdr *eth = pktgen__push_ethhdr(&builder);
	if (!eth) return DROP_INVALID;
	ethhdr__set_macs(eth, (unsigned char *)mac_one, (unsigned char *)mac_two);
	eth->h_proto = bpf_htons(ETH_P_IP);

	// Push IP header as "padding" to remove (20 bytes)
	struct iphdr *ip = pktgen__push_default_iphdr(&builder);
	if (!ip) return DROP_INVALID;

	// Payload
	char payload[] = "payload";
	if (pktgen__push_data(&builder, payload, sizeof(payload)) == NULL)
		return DROP_INVALID;

	pktgen__finish(&builder);
	return 0;
}

CHECK("xdp", "shrink")
int test_shrink_check(struct __ctx_buff *ctx)
{
	test_init();

	// Remove IP header (20 bytes)
	int ret = google_ctx_adjust_hroom(ctx, -20, BPF_ADJ_ROOM_MAC, 0);
	if (ret)
		test_fatal("adjust_hroom failed: %d", ret);

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u64 len = data_end - data;
	// Expected: ETH(14) + Payload(8) = 22
	if (len != 22)
		test_fatal("unexpected length: %llu, want 22", len);

	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		test_fatal("truncated eth");

	if (eth->h_source[5] != 0xEF || eth->h_dest[5] != 0x37)
		test_fatal("eth header corrupted");
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("eth proto corrupted");

	// Verify payload is now after ETH
	char *payload = (char *)(eth + 1);
	if ((void *)(payload + 8) > data_end)
		test_fatal("truncated payload");

	if (memcmp(payload, "payload", 8) != 0)
		test_fatal("payload mismatch");

	test_finish();
}

PKTGEN("xdp", "grow")
int test_grow_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	struct ethhdr *eth = pktgen__push_ethhdr(&builder);
	if (!eth) return DROP_INVALID;
	ethhdr__set_macs(eth, (unsigned char *)mac_one, (unsigned char *)mac_two);
	eth->h_proto = bpf_htons(ETH_P_IP);

	// Payload
	char payload[] = "payload";
	if (pktgen__push_data(&builder, payload, sizeof(payload)) == NULL)
		return DROP_INVALID;

	pktgen__finish(&builder);
	return 0;
}

CHECK("xdp", "grow")
int test_grow_check(struct __ctx_buff *ctx)
{
	test_init();

	// Add 20 bytes
	int ret = google_ctx_adjust_hroom(ctx, 20, BPF_ADJ_ROOM_MAC, 0);
	if (ret)
		test_fatal("adjust_hroom failed: %d", ret);

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	__u64 len = data_end - data;
	// Expected: ETH(14) + GAP(20) + Payload(8) = 42.
	if (len != 42)
		test_fatal("unexpected length: %llu, want 42", len);

	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		test_fatal("truncated eth");

	if (eth->h_source[5] != 0xEF || eth->h_dest[5] != 0x37)
		test_fatal("eth header corrupted");
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("eth proto corrupted");

	void *gap = (void *)(eth + 1);
	if (gap + 20 > data_end)
		test_fatal("truncated gap");

	memset(gap, 0xAA, 20);

	char *payload = (char *)(gap + 20);
	if ((void *)(payload + 8) > data_end)
		test_fatal("truncated payload");

	if (memcmp(payload, "payload", 8) != 0)
		test_fatal("payload mismatch");

	test_finish();
}
