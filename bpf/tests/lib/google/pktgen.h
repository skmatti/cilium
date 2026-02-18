#pragma once

#include <tests/common.h>
#include <tests/pktgen.h>
#include <node_config.h>
#include <lib/google/geneve.h>
#include <lib/google_perimeter_common.h>
#include <lib/conntrack.h>
#include <lib/conntrack_map.h>

#define assert_num_equal(expected_num, result_num)                                \
	({                                                                      \
		if ((expected_num) != (result_num)) {                                 \
			test_log("assert failed at " __FILE__ ":" LINE_STRING); \
			test_error("-- expected: %d  got: %d", (expected_num),     \
				   (result_num))                                   \
		}                                                               \
	})

#define assert_ip_equal(expected_ip, result_ip)                                    \
	({                                                                       \
		if ((expected_ip) != (result_ip)) {                                    \
			__u32 exp1 = ((expected_ip) >> 24) & 0xFF;                  \
			__u32 exp2 = ((expected_ip) >> 16) & 0xFF;                  \
			__u32 exp3 = ((expected_ip) >> 8) & 0xFF;                   \
			__u32 exp4 = ((expected_ip)) & 0xFF;                        \
			__u32 recv1 = ((result_ip) >> 24) & 0xFF;                   \
			__u32 recv2 = ((result_ip) >> 16) & 0xFF;                   \
			__u32 recv3 = ((result_ip) >> 8) & 0xFF;                    \
			__u32 recv4 = ((result_ip)) & 0xFF;                         \
			test_log("line %d: ip address not equal", __LINE__);     \
			test_error("-- expected: %d.%d.%d.%d  got: %d.%d.%d.%d", \
				   exp4, exp3, exp2, exp1, recv4, recv3,         \
				   recv2, recv1);                                \
		}                                                                \
	})

#include <lib/tunnel.h>

enum google_pktgen__geneve_direction {
	GENEVE_INGRESS_CLUSTER,
	GENEVE_EGRESS_CLUSTER,
};

enum google_pktgen__geneve_opt_type {
	GENEVE_OPT_TYPE_NONE = 0,
	GENEVE_OPT_TYPE_PERIMETER,
	GENEVE_OPT_TYPE_DSR,
};

struct google_pktgen__genevehdr_params {
	__u8 *src_mac;
	__u8 *dst_mac;

	__be32 outer_src_ip;
	__be32 outer_dst_ip;

	__u16 outer_src_port;
	__u16 outer_dst_port;

	enum google_pktgen__geneve_direction direction;

	// Option configuration
	enum google_pktgen__geneve_opt_type opt_type; // Defaults to PERIMETER (0)

	__u32 vni;

	// Perimeter option fields
	__be32 perimeter_node;

	// DSR option fields
	__be32 dsr_addr;
	__be16 dsr_port;
};

static __always_inline
int google_pktgen__push_genevehdr(struct pktgen *builder __maybe_unused,
				  struct google_pktgen__genevehdr_params params __maybe_unused)
{
	/* Ethernet Header */
	struct ethhdr *outer_l2 = pktgen__push_ethhdr(builder);

	if (!outer_l2)
		return TEST_ERROR;

	ethhdr__set_macs(outer_l2, params.src_mac, params.dst_mac);

	/* Outer IPv4 Header */
	struct iphdr *outer_l3 = pktgen__push_default_iphdr(builder);

	if (!outer_l3)
		return TEST_ERROR;

	outer_l3->protocol = (__u8)IPPROTO_UDP;
	outer_l3->saddr = params.outer_src_ip;
	outer_l3->daddr = params.outer_dst_ip;

	/* Outer UDP Header */
	struct udphdr *outer_l4 = pktgen__push_default_udphdr(builder);

	if (!outer_l4)
		return TEST_ERROR;

	outer_l4->source = bpf_htons(params.outer_src_port);
	outer_l4->dest = bpf_htons(params.outer_dst_port);

	/* Geneve Header */
	__u8 opt_len = 0;
	if (params.opt_type != GENEVE_OPT_TYPE_NONE) {
		if (params.opt_type == GENEVE_OPT_TYPE_DSR) {
			opt_len = sizeof(struct geneve_dsr_opt4);
		} else {
			opt_len = sizeof(struct geneve_perimeter_opt4);
		}
	}

	struct genevehdr *geneve_hdr = pktgen__push_default_genevehdr_with_options(builder, opt_len);

	if (!geneve_hdr)
		return TEST_ERROR;

	/* Geneve Header Fields */
	geneve_hdr->ver = GENEVE_VERSION;
	geneve_hdr->opt_len = opt_len / 4;
	geneve_hdr->protocol_type = bpf_htons(ETH_P_IP);

	geneve_hdr->vni[0] = (__u8)(params.vni >> 16);
	geneve_hdr->vni[1] = (__u8)(params.vni >> 8);
	geneve_hdr->vni[2] = (__u8)(params.vni);

	if (params.opt_type == GENEVE_OPT_TYPE_NONE)
		return TEST_PASS;

	/* Geneve Option Header Fields */
	void *opt_data = (void *)geneve_hdr + sizeof(struct genevehdr);

	if ((opt_data + opt_len) > (void *)(long)builder->ctx->data_end) {
		return TEST_ERROR;
	}

	if (params.opt_type == GENEVE_OPT_TYPE_DSR) {
		struct geneve_dsr_opt4 *dsr = opt_data;
		dsr->hdr.opt_class = bpf_htons(DSR_GENEVE_OPT_CLASS);
		dsr->hdr.type = DSR_GENEVE_OPT_TYPE;
		dsr->hdr.length = DSR_IPV4_GENEVE_OPT_LEN;
		dsr->addr = params.dsr_addr;
		dsr->port = params.dsr_port;
		dsr->pad = 0;
	} else {
		struct geneve_perimeter_opt4 *perim = opt_data;
		perim->hdr.opt_class = bpf_htons(GOOGLE_GENEVE_OPT_CLASS);
		perim->hdr.length = PERIMETER_IPV4_GENEVE_OPT_LEN;

		if (params.direction == GENEVE_INGRESS_CLUSTER) {
			perim->hdr.type = PERIMETER_GENEVE_INGRESS_OPT_TYPE;
		} else {
			perim->hdr.type = PERIMETER_GENEVE_EGRESS_OPT_TYPE;
		}
		perim->addr = params.perimeter_node;
	}

	return TEST_PASS;
}

static __always_inline
int google_pktgen__create_existing_conn_tcp(struct __ctx_buff *ctx,
					    __be32 saddr,
					    __be32 daddr,
					    __be16 sport,
					    __be16 dport,
					    struct ct_state ct_state)
{
	struct ipv4_ct_tuple tuple = {};

	tuple.nexthdr = IPPROTO_TCP;
	tuple.flags = TUPLE_F_IN;

	tuple.saddr = saddr;
	tuple.daddr = daddr;

	tuple.sport = dport;
	tuple.dport = sport;

	int ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, ctx, CT_EGRESS,
		&ct_state, NULL);

	/*
	 * Return codes from core library functions do not operate the same as the
	 * test flags
	 */
	if (ret != 0)
		return TEST_ERROR;

	return TEST_PASS;
}

static __always_inline void
google_pktgen__finish_geneve_pkt(const struct pktgen *builder)
{
	/* OUTER PACKET */
	pktgen__finish_eth(builder, 0);
	pktgen__finish_ipv4(builder, 1);
	pktgen__finish_udp(builder, 2);

	/* Geneve Header */
	pktgen__finish_geneve(builder, 3);

	/* Inner Packet */
	pktgen__finish_ipv4(builder, 4);
	pktgen__finish_tcp(builder, 5);
}
