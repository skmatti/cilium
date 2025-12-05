#include "common.h"
#include "bpf/ctx/skb.h"

#define ENABLE_GOOGLE_GENEVE
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define SECLABEL 2222
#define ENCAP_IFINDEX 4

#include "node_config.h"
#include "lib/common.h"
#include "lib/maps.h"

// Mock tail_call_internal
static int mock_tail_call_called = 0;
static __always_inline int mock_tail_call(struct __ctx_buff *ctx __maybe_unused, const __u32 index __maybe_unused, __s8 *ext_err)
{
	mock_tail_call_called = 1;
	if (ext_err) *ext_err = 0;
	return DROP_MISSED_TAIL_CALL;
}

#define tail_call_internal mock_tail_call

#include "lib/drop.h"
#include "lib/google/geneve.h"
#include "lib/google/pktgen.h"
#include "lib/tunnel.h"


PKTGEN("tc", "geneve_decap4")
int test_geneve_decap4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	struct google_pktgen__genevehdr_params params = {
		.src_mac = (unsigned char[]){1, 2, 3, 4, 5, 6},
		.dst_mac = (unsigned char[]){1, 2, 3, 4, 5, 7},
		.outer_src_ip = bpf_htonl(0x0A000101),
		.outer_dst_ip = IPV4_DIRECT_ROUTING,
		.outer_src_port = 1234,
		.outer_dst_port = TUNNEL_PORT,
		.vni = 0x1234,
		.opt_type = GENEVE_OPT_TYPE_NONE,
	};

	if (google_pktgen__push_genevehdr(&builder, params) == TEST_ERROR) return TEST_ERROR;

	// Inner IP
	struct iphdr *inner_ip = pktgen__push_default_iphdr(&builder);
	if (!inner_ip)
		return TEST_ERROR;
	inner_ip->saddr = bpf_htonl(0x01010101); // 1.1.1.1
	inner_ip->daddr = bpf_htonl(0x02020202); // 2.2.2.2

	// Inner UDP
	struct udphdr *inner_udp = pktgen__push_default_udphdr(&builder);
	if (!inner_udp) return TEST_ERROR;
	inner_udp->source = bpf_htons(1111);
	inner_udp->dest = bpf_htons(2222);

	// Payload
	char payload[] = "deadbeef";
	if (!pktgen__push_data(&builder, payload, sizeof(payload)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return TEST_PASS;
}

CHECK("tc", "geneve_decap4")
int test_geneve_decap4_check(struct __ctx_buff *ctx)
{
	test_init();

	struct geneve_metadata metadata = {};

	// Call geneve_decap4
	int ret = geneve_decap4(ctx, &metadata);
	if (ret != CTX_ACT_OK) {
		test_fatal("geneve_decap4 failed: %d\n", ret);
	}

	// Verify metadata
	if (metadata.tunnel_key.tunnel_id != 0x1234) {
		test_fatal("tunnel_id mismatch: got %x, want %x\n", metadata.tunnel_key.tunnel_id, 0x1234);
	}

	// Verify packet is decapsulated (check protocol is IP, not Geneve/UDP)
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end) return TEST_ERROR;

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		test_fatal("eth proto mismatch: got %x, want %x\n", bpf_ntohs(eth->h_proto), ETH_P_IP);
	}

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TEST_ERROR;

	if (ip->saddr != bpf_htonl(0x01010101)) {
		test_fatal("inner ip src mismatch: got %x, want %x\n",
			   bpf_ntohl(ip->saddr), 0x01010101);
	}
	if (ip->daddr != bpf_htonl(0x02020202)) {
		test_fatal("inner ip dst mismatch: got %x, want %x\n",
			   bpf_ntohl(ip->daddr), 0x02020202);
	}
	if (ip->protocol != IPPROTO_UDP) {
		test_fatal("inner ip proto mismatch: got %d, want %d\n",
			   ip->protocol, IPPROTO_UDP);
	}

	struct udphdr *udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end)
		return TEST_ERROR;

	if (udp->source != bpf_htons(1111)) {
		test_fatal("inner udp src mismatch: got %d, want %d\n",
			   bpf_ntohs(udp->source), 1111);
	}
	if (udp->dest != bpf_htons(2222)) {
		test_fatal("inner udp dst mismatch: got %d, want %d\n",
			   bpf_ntohs(udp->dest), 2222);
	}

	char payload[9]; // "deadbeef" + null
	if (ctx_load_bytes(ctx, ETH_HLEN + sizeof(*ip) + sizeof(*udp), payload,
			   sizeof(payload)) < 0) {
		test_fatal("failed to load inner payload\n");
	}
	// Simple check of first few bytes or use a helper if available, or memcmp if possible
	// Verify full payload "deadbeef" (including null terminator)
	char expected[] = "deadbeef";
	if (memcmp(payload, expected, sizeof(expected)) != 0) {
		test_fatal("inner payload mismatch\n");
	}

	test_finish();
}

PKTGEN("tc", "geneve_encap4")
int test_geneve_encap4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	// Use explicit MACs so we can verify them later (geneve_encap4 preserves L2)
	struct ethhdr *eth = pktgen__push_ethhdr(&builder);
	if (!eth)
		return TEST_ERROR;
	ethhdr__set_macs(eth, (unsigned char[]){ 1, 2, 3, 4, 5, 6 },
			 (unsigned char[]){ 1, 2, 3, 4, 5, 7 });
	// Inner IP
	struct iphdr *ip = pktgen__push_default_iphdr(&builder);
	if (!ip)
		return TEST_ERROR;
	ip->saddr = bpf_htonl(0x01010101);
	ip->daddr = bpf_htonl(0x02020202);

	// Inner UDP
	struct udphdr *udp = pktgen__push_default_udphdr(&builder);
	if (!udp)
		return TEST_ERROR;
	udp->source = bpf_htons(1111);
	udp->dest = bpf_htons(2222);

	// Payload
	char payload[] = "deadbeef";
	if (!pktgen__push_data(&builder, payload, sizeof(payload)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return TEST_PASS;
}

CHECK("tc", "geneve_encap4")
int test_geneve_encap4_check(struct __ctx_buff *ctx)
{
	test_init();

	struct geneve_metadata metadata = {};
	metadata.tunnel_key.tunnel_id = 0x5678;
	metadata.tunnel_key.remote_ipv4 = 0x01020304; // 1.2.3.4

	struct geneve_encaphdr4 hdr = {};

	int ret = geneve_encap4(ctx, &metadata, &hdr);
	if (ret != CTX_ACT_REDIRECT) {
		test_fatal("geneve_encap4 failed: %d\n", ret);
	}

	// Verify header
	if (genevehdr_vni(&hdr.geneve) != 0x5678) {
		test_fatal("encap vni mismatch: got %x, want %x\n", genevehdr_vni(&hdr.geneve), 0x5678);
	}

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end) {
		test_fatal("packet too short for eth\n");
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		test_fatal("encap eth proto mismatch: got %x, want %x\n",
			   bpf_ntohs(eth->h_proto), ETH_P_IP);
	}
	// Verify explicit MACs
	unsigned char expected_src[] = { 1, 2, 3, 4, 5, 6 };
	unsigned char expected_dst[] = { 1, 2, 3, 4, 5, 7 };

	if (memcmp(eth->h_source, expected_src, ETH_ALEN) != 0) {
		test_fatal("encap src mac mismatch\n");
	}
	if (memcmp(eth->h_dest, expected_dst, ETH_ALEN) != 0) {
		test_fatal("encap dst mac mismatch\n");
	}

	// Verify Inner Packet (skipped outer headers)
	// Outer Eth(14) + IP(20) + UDP(8) + Geneve(8) + Options(0) = 50
	__u32 inner_offset = 50;
	struct iphdr inner_ip;
	if (ctx_load_bytes(ctx, inner_offset, &inner_ip, sizeof(inner_ip)) < 0) {
		test_fatal("failed to load inner ip\n");
	}
	if (inner_ip.saddr != bpf_htonl(0x01010101)) {
		test_fatal("encap inner ip src mismatch: got %x, want %x\n",
			   bpf_ntohl(inner_ip.saddr), 0x01010101);
	}
	if (inner_ip.daddr != bpf_htonl(0x02020202)) {
		test_fatal("encap inner ip dst mismatch: got %x, want %x\n",
			   bpf_ntohl(inner_ip.daddr), 0x02020202);
	}

	struct udphdr inner_udp;
	if (ctx_load_bytes(ctx, inner_offset + sizeof(inner_ip), &inner_udp,
			   sizeof(inner_udp)) < 0) {
		test_fatal("failed to load inner udp\n");
	}
	if (inner_udp.source != bpf_htons(1111)) {
		test_fatal("encap inner udp src mismatch: got %d, want %d\n",
			   bpf_ntohs(inner_udp.source), 1111);
	}

	char payload[9];
	if (ctx_load_bytes(
		    ctx, inner_offset + sizeof(inner_ip) + sizeof(inner_udp),
		    payload, sizeof(payload)) < 0) {
		test_fatal("failed to load inner payload\n");
	}
	// Verify full payload "deadbeef" (including null terminator)
	char expected[] = "deadbeef";
	if (memcmp(payload, expected, sizeof(expected)) != 0) {
		test_fatal("encap inner payload mismatch\n");
	}

	test_finish();
}

PKTGEN("tc", "geneve_try_decap4_non_geneve")
int test_geneve_try_decap4_non_geneve_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	if (!pktgen__push_ethhdr(&builder)) return TEST_ERROR;
	if (!pktgen__push_default_iphdr(&builder)) return TEST_ERROR;
	if (!pktgen__push_default_udphdr(&builder)) return TEST_ERROR;
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data))) return TEST_ERROR;

	pktgen__finish(&builder);
	return TEST_PASS;
}

CHECK("tc", "geneve_try_decap4_non_geneve")
int test_geneve_try_decap4_non_geneve_check(struct __ctx_buff *ctx)
{
	test_init();

	mock_tail_call_called = 0;
	int ret = geneve_try_decap4(ctx);
	if (ret != HOOK_ACT_CONTINUE) {
		test_fatal("geneve_try_decap4 should continue for non-geneve packet, got %d\n", ret);
	}
	if (mock_tail_call_called) {
		test_fatal("geneve_try_decap4 should not call tail call for non-geneve packet\n");
	}

	test_finish();
}

// Test 4: geneve_try_decap4 with Geneve packet
PKTGEN("tc", "geneve_try_decap4_geneve")
int test_geneve_try_decap4_geneve_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct genevehdr *geneve;
	struct iphdr *outer_ip;
	struct udphdr *outer_udp;
	struct ethhdr *eth;

	pktgen__init(&builder, ctx);

	eth = pktgen__push_ethhdr(&builder);
	if (!eth) return TEST_ERROR;

	outer_ip = pktgen__push_default_iphdr(&builder);
	if (!outer_ip) return TEST_ERROR;
	outer_ip->protocol = IPPROTO_UDP;
	outer_ip->daddr = IPV4_DIRECT_ROUTING;

	outer_udp = pktgen__push_default_udphdr(&builder);
	if (!outer_udp) return TEST_ERROR;
	outer_udp->dest = bpf_htons(TUNNEL_PORT);

	geneve = pktgen__push_genevehdr(&builder, 0);
	if (!geneve) return TEST_ERROR;
	*(__u64 *)geneve = 0;
	geneve->protocol_type = bpf_htons(ETH_P_IP);

	if (!pktgen__push_default_iphdr(&builder)) return TEST_ERROR;
	if (!pktgen__push_default_udphdr(&builder)) return TEST_ERROR;
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data))) return TEST_ERROR;

	pktgen__finish(&builder);
	return TEST_PASS;
}

CHECK("tc", "geneve_try_decap4_geneve")
int test_geneve_try_decap4_geneve_check(struct __ctx_buff *ctx)
{
	test_init();

	mock_tail_call_called = 0;
	int ret = geneve_try_decap4(ctx);

	// Since we mock tail_call_internal to return DROP_MISSED_TAIL_CALL,
	// geneve_try_decap4 should return that.
	if (ret != DROP_MISSED_TAIL_CALL) {
		test_fatal("geneve_try_decap4 should try tail call, got %d\n", ret);
	}
	if (!mock_tail_call_called) {
		test_fatal("geneve_try_decap4 should call tail call for geneve packet\n");
	}

	test_finish();
}

PKTGEN("tc", "geneve_decap4_with_options")
int test_geneve_decap4_with_options_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	struct google_pktgen__genevehdr_params params = {
		.src_mac = (unsigned char[]){1, 2, 3, 4, 5, 6},
		.dst_mac = (unsigned char[]){1, 2, 3, 4, 5, 7},
		.outer_src_ip = bpf_htonl(0x0A000101),
		.outer_dst_ip = IPV4_DIRECT_ROUTING,
		.outer_src_port = 1234,
		.outer_dst_port = TUNNEL_PORT,
		.vni = 0x1234,
		.opt_type = GENEVE_OPT_TYPE_DSR,
		.dsr_addr = bpf_htonl(0x0A000001),
		.dsr_port = bpf_htons(8080),
	};

	if (google_pktgen__push_genevehdr(&builder, params) == TEST_ERROR) return TEST_ERROR;

	// Inner Headers
	if (!pktgen__push_default_iphdr(&builder)) return TEST_ERROR;
	if (!pktgen__push_default_udphdr(&builder)) return TEST_ERROR;

	char data[64] = {};
	if (!pktgen__push_data(&builder, data, sizeof(data))) return TEST_ERROR;

	pktgen__finish(&builder);
	return TEST_PASS;
}

CHECK("tc", "geneve_decap4_with_options")
int test_geneve_decap4_with_options_check(struct __ctx_buff *ctx)
{
	test_init();

	__u32 zero = 0;
	struct geneve_metadata *metadata = map_lookup_elem(&GOOGLE_GENEVE_METADATA, &zero);
	if (!metadata) {
		test_fatal("failed to lookup metadata map\n");
	}

	// Clear metadata manually since we are reusing map memory
	memset(metadata, 0, sizeof(*metadata));

	int ret;

	if (ctx->len < 62) return -100;

	ret = geneve_decap4(ctx, metadata);
	if (ret != CTX_ACT_OK) {
		test_fatal("geneve_decap4 failed: %d\n", ret);
	}

	// Verify metadata
	if (metadata->tunnel_key.tunnel_id != 0x1234) {
		test_fatal("tunnel_id mismatch: got %x, want %x\n", metadata->tunnel_key.tunnel_id, 0x1234);
	}

	// EXPECT 1 DSR OPTION
	if (metadata->opt_count != 1) {
		test_fatal("opt_count mismatch: got %d, want 1\n", metadata->opt_count);
	}
	// Verify DSR content in opt_data
	struct geneve_dsr_opt4 *dsr = (void *)metadata->raw_opt_data;

	if (dsr->hdr.opt_class != bpf_htons(DSR_GENEVE_OPT_CLASS)) {
		test_fatal("opt_class mismatch: got %x, want %x\n", bpf_ntohs(dsr->hdr.opt_class), DSR_GENEVE_OPT_CLASS);
	}
	if (dsr->hdr.type != DSR_GENEVE_OPT_TYPE) {
		test_fatal("opt_type mismatch: got %x, want %x\n", dsr->hdr.type, DSR_GENEVE_OPT_TYPE);
	}
	if (dsr->addr != bpf_htonl(0x0A000001)) {
		test_fatal("dsr addr mismatch: got %x, want %x\n", bpf_ntohl(dsr->addr), 0x0A000001);
	}

	test_finish();
}

// Test 6: geneve_encap4 with DSR option
PKTGEN("tc", "geneve_encap4_with_options")
int test_geneve_encap4_with_options_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	// Use explicit MACs so we can verify them later (geneve_encap4 preserves L2)
	struct ethhdr *eth = pktgen__push_ethhdr(&builder);
	if (!eth)
		return TEST_ERROR;
	ethhdr__set_macs(eth, (unsigned char[]){ 1, 2, 3, 4, 5, 6 },
			 (unsigned char[]){ 1, 2, 3, 4, 5, 7 });
	// Inner IP
	struct iphdr *ip = pktgen__push_default_iphdr(&builder);
	if (!ip)
		return TEST_ERROR;
	ip->saddr = bpf_htonl(0x01010101);
	ip->daddr = bpf_htonl(0x02020202);

	// Inner UDP
	struct udphdr *udp = pktgen__push_default_udphdr(&builder);
	if (!udp)
		return TEST_ERROR;
	udp->source = bpf_htons(1111);
	udp->dest = bpf_htons(2222);

	// Payload
	char payload[] = "deadbeef";
	if (!pktgen__push_data(&builder, payload, sizeof(payload)))
		return TEST_ERROR;

	pktgen__finish(&builder);
	return TEST_PASS;
}

CHECK("tc", "geneve_encap4_with_options")
int test_geneve_encap4_with_options_check(struct __ctx_buff *ctx)
{
	test_init();

	struct geneve_metadata metadata = {};
	metadata.tunnel_key.tunnel_id = 0x5678;
	metadata.tunnel_key.remote_ipv4 = 0x01020304; // 1.2.3.4

	// Add DSR option to metadata
	metadata.opt_count = 1;
	struct geneve_dsr_opt4 *opt = (struct geneve_dsr_opt4 *)metadata.raw_opt_data;
	opt->hdr.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS);
	opt->hdr.type = DSR_GENEVE_OPT_TYPE;
	opt->hdr.length = DSR_IPV4_GENEVE_OPT_LEN;
	opt->addr = bpf_htonl(0x0A000001);
	opt->port = bpf_htons(8080);

	struct geneve_encaphdr4 hdr = {};

	int ret = geneve_encap4(ctx, &metadata, &hdr);
	if (ret != CTX_ACT_REDIRECT) {
		test_fatal("geneve_encap4 failed: %d\n", ret);
	}

	// Verify header
	if (genevehdr_vni(&hdr.geneve) != 0x5678) {
		test_fatal("encap vni mismatch: got %x, want %x\n", genevehdr_vni(&hdr.geneve), 0x5678);
	}

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end) {
		test_fatal("packet too short for eth\n");
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		test_fatal("encap eth proto mismatch: got %x, want %x\n",
			   bpf_ntohs(eth->h_proto), ETH_P_IP);
	}
	// Verify explicit MACs
	unsigned char expected_src[] = { 1, 2, 3, 4, 5, 6 };
	unsigned char expected_dst[] = { 1, 2, 3, 4, 5, 7 };

	if (memcmp(eth->h_source, expected_src, ETH_ALEN) != 0) {
		test_fatal("encap src mac mismatch\n");
	}
	if (memcmp(eth->h_dest, expected_dst, ETH_ALEN) != 0) {
		test_fatal("encap dst mac mismatch\n");
	}

	// Verify option length in header (3 * 4 = 12 bytes)
	if (hdr.geneve.opt_len != 3) {
		test_fatal("encap opt_len mismatch: got %d, want 3\n", hdr.geneve.opt_len);
	}

	// Verify Option Content by loading from packet.
	// Header len: Eth(14) + IP(20) + UDP(8) + Geneve(8) + Options(12) = 62.
	// Options start at 14+20+8+8 = 50.
	struct geneve_dsr_opt4 out_opt;
	if (ctx_load_bytes(ctx, 50, &out_opt, sizeof(out_opt)) < 0) {
		test_fatal("failed to load encapsulated options\n");
	}
	if (out_opt.addr != bpf_htonl(0x0A000001)) {
		test_fatal("encap opt addr mismatch: got %x, want %x\n", bpf_ntohl(out_opt.addr), 0x0A000001);
	}
	if (out_opt.port != bpf_htons(8080)) {
		test_fatal("encap opt port mismatch: got %x, want %x\n", bpf_ntohs(out_opt.port), 8080);
	}

	// Verify Inner Packet
	// Outer Eth(14) + IP(20) + UDP(8) + Geneve(8) + Options(12) = 62
	__u32 inner_offset = 62;
	struct iphdr inner_ip;
	if (ctx_load_bytes(ctx, inner_offset, &inner_ip, sizeof(inner_ip)) < 0) {
		test_fatal("failed to load inner ip\n");
	}
	if (inner_ip.saddr != bpf_htonl(0x01010101)) {
		test_fatal("encap inner ip src mismatch: got %x, want %x\n",
			   bpf_ntohl(inner_ip.saddr), 0x01010101);
	}

	struct udphdr inner_udp;
	if (ctx_load_bytes(ctx, inner_offset + sizeof(inner_ip), &inner_udp,
			   sizeof(inner_udp)) < 0) {
		test_fatal("failed to load inner udp\n");
	}
	if (inner_udp.source != bpf_htons(1111)) {
		test_fatal("encap inner udp src mismatch: got %d, want %d\n",
			   bpf_ntohs(inner_udp.source), 1111);
	}

	char payload[9];
	if (ctx_load_bytes(
		    ctx, inner_offset + sizeof(inner_ip) + sizeof(inner_udp),
		    payload, sizeof(payload)) < 0) {
		test_fatal("failed to load inner payload\n");
	}
	// Verify full payload "deadbeef" (including null terminator)
	char expected[] = "deadbeef";
	if (memcmp(payload, expected, sizeof(expected)) != 0) {
		test_fatal("encap inner payload mismatch\n");
	}

	test_finish();
}
