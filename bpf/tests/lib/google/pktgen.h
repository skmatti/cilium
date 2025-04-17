#pragma once

#include <tests/common.h>
#include <tests/pktgen.h>
#include <node_config.h>
#include <lib/google/geneve.h>

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

enum google_pktgen__geneve_direction {
	GENEVE_INGRESS_CLUSTER,
	GENEVE_EGRESS_CLUSTER,
};

struct google_pktgen__genevehdr_params {
	__u8 *src_mac;
	__u8 *dst_mac;

	__be32 outer_src_ip;
	__be32 outer_dst_ip;

	__u16 outer_src_port;
	__u16 outer_dst_port;

	enum google_pktgen__geneve_direction direction;

	__be32 perimeter_node;
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
	struct genevehdr *geneve_hdr = pktgen__push_default_genevehdr_with_options(builder,
		(__u8)sizeof(struct geneve_perimeter_opt4));

	if (!geneve_hdr)
		return TEST_ERROR;

	/* Geneve Header Fields */
	geneve_hdr->ver = GENEVE_VERSION;
	geneve_hdr->opt_len = sizeof(struct geneve_perimeter_opt4) / 4;
	geneve_hdr->protocol_type = bpf_htons(ETH_P_IP);

	geneve_hdr->vni[0] = 0;
	geneve_hdr->vni[1] = 0;
	geneve_hdr->vni[2] = 0;

	/* TODO: Later add option to skip geneve options if its just in-cluster traffic */

	/* Geneve Option Header Fields */
	struct geneve_perimeter_opt4 *geneve_perimeter_opt_data =
		(void *)geneve_hdr + sizeof(struct genevehdr);

	if (((void *)geneve_perimeter_opt_data +
	     sizeof(struct geneve_perimeter_opt4)) >
	    (void *)(long)builder->ctx->data_end) {
		return TEST_ERROR;
	}

	geneve_perimeter_opt_data->hdr.opt_class =
		bpf_htons(GOOGLE_GENEVE_OPT_CLASS);
	geneve_perimeter_opt_data->hdr.length =
		(sizeof(struct geneve_perimeter_opt4) -
		 sizeof(geneve_perimeter_opt_data->hdr)) /
		4;

	if (params.direction == GENEVE_INGRESS_CLUSTER) {
		geneve_perimeter_opt_data->hdr.type =
			PERIMETER_GENEVE_INGRESS_OPT_TYPE;
	} else {
		geneve_perimeter_opt_data->hdr.type =
			PERIMETER_GENEVE_EGRESS_OPT_TYPE;
	}

	geneve_perimeter_opt_data->addr = params.perimeter_node;

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
