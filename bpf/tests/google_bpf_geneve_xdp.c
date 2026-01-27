#include "common.h"
#include <bpf/ctx/xdp.h>
#include "lib/google/xdp.h"

#define ENABLE_GOOGLE_GENEVE
#define ENABLE_IPV4
// #define ENABLE_IPV6
#define ENABLE_NODEPORT
#define ENABLE_DSR
#define DSR_ENCAP_IPIP	 2
#define DSR_ENCAP_GENEVE 3
#define DSR_ENCAP_MODE	 DSR_ENCAP_GENEVE
#define DSR_ENCAP_NONE	 1
#define SECLABEL	 2222
#define ENCAP_IFINDEX	 4

#include "node_config.h"
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/tunnel.h"

// Mock tail_call_internal
static int mock_tail_call_called = 0;
static __always_inline int
mock_tail_call(struct __ctx_buff *ctx __maybe_unused,
	       const __u32 index __maybe_unused, __s8 *ext_err)
{
	mock_tail_call_called = 1;
	if (ext_err)
		*ext_err = 0;
	return DROP_MISSED_TAIL_CALL;
}

#undef tail_call_internal
#define tail_call_internal mock_tail_call

#include "lib/google/geneve.h"
#include "tests/lib/google/pktgen.h"

PKTGEN("xdp", "decap4")
int test_geneve_xdp_decap4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct google_pktgen__genevehdr_params params = {
		.direction = GENEVE_EGRESS_CLUSTER,
		.opt_type = GENEVE_OPT_TYPE_NONE,
		.vni = SECLABEL,
		.outer_src_ip = bpf_htonl(0x0A000101),
		.outer_dst_ip = IPV4_DIRECT_ROUTING,
		.outer_src_port = 1234,
		.outer_dst_port = TUNNEL_PORT,
		.src_mac = (unsigned char *)mac_one,
		.dst_mac = (unsigned char *)mac_two,
	};

	pktgen__init(&builder, ctx);

	if (google_pktgen__push_genevehdr(&builder, params) < 0)
		return DROP_INVALID;

	// Inner IP
	struct iphdr *inner_ip = pktgen__push_default_iphdr(&builder);
	if (!inner_ip)
		return DROP_INVALID;
	inner_ip->saddr = bpf_htonl(0x01010101);
	inner_ip->daddr = bpf_htonl(0x02020202);

	// Inner TCP
	struct tcphdr *inner_tcp = pktgen__push_default_tcphdr(&builder);
	if (!inner_tcp)
		return DROP_INVALID;
	inner_tcp->source = bpf_htons(1111);
	inner_tcp->dest = bpf_htons(2222);

	// Payload
	char payload[] = "payload";
	if (pktgen__push_data(&builder, payload, sizeof(payload)) == NULL)
		return DROP_INVALID;

	google_pktgen__finish_geneve_pkt(&builder);

	return 0;
}

CHECK("xdp", "decap4")
int test_geneve_xdp_decap4_check(struct __ctx_buff *ctx)
{
	struct geneve_metadata meta = {};
	test_init();

	int ret = geneve_decap4(ctx, &meta);
	if (ret != CTX_ACT_OK)
		test_fatal("geneve_decap4 failed: %d", ret);

	if (meta.tunnel_key.tunnel_id != SECLABEL)
		test_fatal("tunnel_id mismatch: got %lx, want %lx",
			   meta.tunnel_key.tunnel_id, SECLABEL);

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		test_fatal("packet truncated");

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		test_fatal("eth proto mismatch: %x", bpf_ntohs(eth->h_proto));

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		test_fatal("ip hdr truncated");

	if (ip->saddr != bpf_htonl(0x01010101))
		test_fatal("inner ip src mismatch");
	if (ip->daddr != bpf_htonl(0x02020202))
		test_fatal("inner ip dst mismatch");
	if (ip->protocol != IPPROTO_TCP)
		test_fatal("inner ip proto mismatch");

	struct tcphdr *tcp = (void *)(ip + 1);
	if ((void *)(tcp + 1) > data_end)
		test_fatal("tcp hdr truncated");

	if (tcp->source != bpf_htons(1111))
		test_fatal("tcp src mismatch");
	if (tcp->dest != bpf_htons(2222))
		test_fatal("tcp dst mismatch");

	char payload[8];
	if (ctx_load_bytes(ctx, ETH_HLEN + sizeof(*ip) + sizeof(*tcp), payload, 8) <
	    0)
		test_fatal("failed load payload");
	if (memcmp(payload, "payload", 8) != 0)
		test_fatal("payload mismatch");

	test_finish();
}

PKTGEN("xdp", "encap4")
int test_geneve_xdp_encap4_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	if (!pktgen__push_ipv4_tcp_packet(
		    &builder, (unsigned char *)mac_one,
		    (unsigned char *)mac_two, bpf_htonl(0x01010101),
		    bpf_htonl(0x02020202), bpf_htons(1111), bpf_htons(2222)))
		return DROP_INVALID;

	// Payload
	char payload[] = "payload";
	if (pktgen__push_data(&builder, payload, sizeof(payload)) == NULL)
		return DROP_INVALID;

	pktgen__finish(&builder);
	return 0;
}

CHECK("xdp", "encap4")
int test_geneve_xdp_encap4_check(struct __ctx_buff *ctx)
{
	struct geneve_encaphdr4 hdr = {};
	struct geneve_metadata meta = {};
	int ret;

	// Populate metadata
	meta.tunnel_key.tunnel_id = SECLABEL;
	meta.tunnel_key.remote_ipv4 = 0x01020304;

	test_init();

	ret = geneve_encap4(ctx, &meta, &hdr);
	if (ret != CTX_ACT_REDIRECT)
		test_fatal("geneve_encap4 failed: %d", ret);

	if (genevehdr_vni(&hdr.geneve) != SECLABEL)
		test_fatal("vni mismatch in hdr");

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		test_fatal("truncated");

	struct iphdr *outer_ip = (void *)(eth + 1);
	if ((void *)(outer_ip + 1) > data_end)
		test_fatal("outer ip truncated");
	if (outer_ip->daddr != bpf_htonl(0x01020304))
		test_fatal("outer dst mismatch");

	struct udphdr *outer_udp = (void *)(outer_ip + 1);
	if ((void *)(outer_udp + 1) > data_end)
		test_fatal("outer udp truncated");
	if (outer_udp->dest != bpf_htons(TUNNEL_PORT))
		test_fatal("outer dport mismatch");

	struct genevehdr *geneve = (void *)(outer_udp + 1);
	if ((void *)(geneve + 1) > data_end)
		test_fatal("geneve truncated");
	if (genevehdr_vni(geneve) != SECLABEL)
		test_fatal("geneve vni mismatch");

	struct iphdr *inner_ip = (void *)(geneve + 1);
	if ((void *)(inner_ip + 1) > data_end)
		test_fatal("inner ip truncated");
	if (inner_ip->saddr != bpf_htonl(0x01010101))
		test_fatal("inner src mismatch");

	struct tcphdr *inner_tcp = (void *)(inner_ip + 1);
	if ((void *)(inner_tcp + 1) > data_end)
		test_fatal("inner tcp truncated");
	if (inner_tcp->source != bpf_htons(1111))
		test_fatal("inner sport mismatch");
	if (inner_tcp->dest != bpf_htons(2222))
		test_fatal("inner dport mismatch");

	test_finish();
}

PKTGEN("xdp", "encap_decap_cycle")
int test_geneve_xdp_encap_decap_cycle_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	if (!pktgen__push_ipv4_tcp_packet(
		    &builder, (unsigned char *)mac_one,
		    (unsigned char *)mac_two, bpf_htonl(0x01010101),
		    bpf_htonl(0x02020202), bpf_htons(1111), bpf_htons(2222)))
		return DROP_INVALID;

	char payload[] = "payload";
	if (pktgen__push_data(&builder, payload, sizeof(payload)) == NULL)
		return DROP_INVALID;

	pktgen__finish(&builder);
	return 0;
}

CHECK("xdp", "encap_decap_cycle")
int test_geneve_xdp_encap_decap_cycle_check(struct __ctx_buff *ctx)
{
	struct geneve_encaphdr4 hdr = {};
	struct geneve_metadata meta = {};
	struct geneve_metadata meta_out = {};
	int ret;

	meta.tunnel_key.tunnel_id = SECLABEL;
	meta.tunnel_key.remote_ipv4 = 0x01020304;

	test_init();

	// 1. Encap
	ret = geneve_encap4(ctx, &meta, &hdr);
	if (ret != CTX_ACT_REDIRECT)
		test_fatal("geneve_encap4 failed: %d", ret);

	// 2. Decap
	ret = geneve_decap4(ctx, &meta_out);
	if (ret != CTX_ACT_OK)
		test_fatal("geneve_decap4 failed: %d", ret);

	// 3. Verify Metadata matches
	if (meta_out.tunnel_key.tunnel_id != meta.tunnel_key.tunnel_id)
		test_fatal(
			"tunnel_id mismatch: got %lx, want %lx",
			meta_out.tunnel_key.tunnel_id, meta.tunnel_key.tunnel_id);
	if (meta_out.tunnel_key.remote_ipv4 !=
	    bpf_htonl(meta.tunnel_key.remote_ipv4))
		test_fatal("remote_ipv4 mismatch: got %lx, want %lx",
			   meta_out.tunnel_key.remote_ipv4,
			   bpf_htonl(meta.tunnel_key.remote_ipv4));

	// 4. Verify Inner Packet is restored
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		test_fatal("eth hdr truncated after decap");

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		test_fatal("ip hdr truncated after decap");

	if (ip->saddr != bpf_htonl(0x01010101))
		test_fatal("inner src mismatch");
	if (ip->daddr != bpf_htonl(0x02020202))
		test_fatal("inner dst mismatch");

	test_finish();
}

PKTGEN("xdp", "decap_error_short")
int test_geneve_xdp_decap_error_short_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);
	// Just Eth header, too short for Geneve
	if (!pktgen__push_ethhdr(&builder))
		return DROP_INVALID;
	pktgen__finish_eth(&builder, 0);
	return 0;
}

CHECK("xdp", "decap_error_short")
int test_geneve_xdp_decap_error_short_check(struct __ctx_buff *ctx)
{
	struct geneve_metadata meta = {};
	test_init();

	int ret = geneve_decap4(ctx, &meta);
	if (ret != DROP_INVALID)
		test_fatal("expected DROP_INVALID for short packet, got %d", ret);

	test_finish();
}

PKTGEN("xdp", "decap_with_options")
int test_geneve_xdp_decap_with_options_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct google_pktgen__genevehdr_params params = {
		.direction = GENEVE_INGRESS_CLUSTER,
		.opt_type = GENEVE_OPT_TYPE_PERIMETER,
		.vni = SECLABEL,
		.outer_src_ip = bpf_htonl(0x01020304),
		.outer_dst_ip = IPV4_DIRECT_ROUTING,
		.outer_src_port = 1234,
		.outer_dst_port = TUNNEL_PORT,
		.src_mac = (unsigned char *)mac_one,
		.dst_mac = (unsigned char *)mac_two,
		.perimeter_node = bpf_htonl(0xDEADBEEF),
	};

	pktgen__init(&builder, ctx);

	if (google_pktgen__push_genevehdr(&builder, params) < 0)
		return DROP_INVALID;

	// Inner IP
	struct iphdr *inner_ip = pktgen__push_default_iphdr(&builder);
	if (!inner_ip)
		return DROP_INVALID;
	inner_ip->saddr = bpf_htonl(0x01010101);
	inner_ip->daddr = bpf_htonl(0x02020202);

	google_pktgen__finish_geneve_pkt(&builder);

	return 0;
}

CHECK("xdp", "decap_with_options")
int test_geneve_xdp_decap_with_options_check(struct __ctx_buff *ctx)
{
	struct geneve_metadata meta = {};
	test_init();

	int ret = geneve_decap4(ctx, &meta);
	if (ret != CTX_ACT_OK)
		test_fatal("geneve_decap4 failed with options: %d", ret);

	if (meta.tunnel_key.tunnel_id != SECLABEL)
		test_fatal("tunnel_id mismatch: got %lx, want %lx",
			   meta.tunnel_key.tunnel_id, SECLABEL);

	if (meta.opt_count != 1)
		test_fatal("expected 1 option, got %d", meta.opt_count);

	struct geneve_perimeter_opt4 *opt = (void *)meta.raw_opt_data;
	if (opt->hdr.opt_class != bpf_htons(GOOGLE_GENEVE_OPT_CLASS))
		test_fatal("opt class mismatch: %x", bpf_ntohs(opt->hdr.opt_class));
	if (opt->hdr.type != PERIMETER_GENEVE_INGRESS_OPT_TYPE)
		test_fatal("opt type mismatch: %x", opt->hdr.type);
	if (opt->hdr.length != PERIMETER_IPV4_GENEVE_OPT_LEN)
		test_fatal("opt length mismatch: %d", opt->hdr.length);
	if (opt->addr != bpf_htonl(0xDEADBEEF))
		test_fatal("opt addr mismatch: %x", bpf_ntohl(opt->addr));

	test_finish();
}

PKTGEN("xdp", "encap_error_data")
int test_geneve_xdp_encap_error_data_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);

	// Push 20 bytes (less than eth+ip) to make sure the packet is invalid
	if (!pktgen__push_data(&builder, (char[20]){ 0 }, 20))
		return DROP_INVALID;

	return 0;
}

CHECK("xdp", "encap_error_data")
int test_geneve_xdp_encap_error_data_check(struct __ctx_buff *ctx)
{
	struct geneve_encaphdr4 hdr = {};
	struct geneve_metadata meta = {};
	test_init();

	// Should fail because packet is empty (no data/eth/ip)
	int ret = geneve_encap4(ctx, &meta, &hdr);
	if (ret != DROP_INVALID)
		test_fatal("expected DROP_INVALID for empty packet, got %d", ret);

	test_finish();
}
