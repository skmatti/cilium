// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_EXTENDED_IP_PROTOCOLS // Enable conntrack for non-TCP/UDP

#include <node_config.h>
#undef EVENTS_MAP
#define EVENTS_MAP test_events_map
#define DEBUG
#include <lib/dbg.h>
#include <lib/conntrack.h>
#include <lib/conntrack_map.h>
#include <lib/time.h>

__always_inline int mkpkt(void *dst, bool first)
{
    void *orig = dst;
	struct ethhdr *l2 = dst;

	l2->h_proto = bpf_htons(ETH_P_IP);

	if (first) {
		char src[6] = {1, 0, 0, 3, 0, 10};
		char dest[6] = {1, 0, 0, 3, 0, 20};

		memcpy(l2->h_source, src, sizeof(src));
		memcpy(l2->h_dest, dest, sizeof(dest));
	} else {
		char src[6] = {1, 0, 0, 3, 0, 20};
		char dest[6] = {1, 0, 0, 3, 0, 10};

		memcpy(l2->h_source, src, sizeof(src));
		memcpy(l2->h_dest, dest, sizeof(dest));
	}

	dst += sizeof(struct ethhdr);

	struct iphdr *l3 = dst;

	l3->version = 4;
	l3->ihl = 5;
	l3->protocol = IPPROTO_IPIP;

	if (first) {
		l3->saddr =  0x0A00030A; /* 10.3.0.10 */
		l3->daddr = 0x1400030A; /* 10.3.0.20 */
	} else {
		l3->saddr = 0x1400030A; /* 10.3.0.20 */
		l3->daddr =  0x0A00030A; /* 10.3.0.10 */
	}

	dst += sizeof(struct iphdr);

    struct iphdr *inner_l3 = dst;

    inner_l3->version = 4;
    inner_l3->ihl = 5;
    inner_l3->protocol = IPPROTO_TCP;
    inner_l3->saddr = 0x01010101;     /* 1.1.1.1 */
    inner_l3->daddr = 0x02020202;     /* 2.2.2.2 */
    dst += sizeof(struct iphdr);

	return dst - orig;
}

static char pkt[100];

CHECK("tc", "ct4")
int test_ct4_rst1_check(__maybe_unused struct __ctx_buff *ctx)
{
	test_init();
    TEST("ct4_ipip", {
		// 1. Create the IP-in-IP packet
		int ipip_pkt_size = mkpkt(pkt, true);
		{
			unsigned int data_len = ctx->data_end - ctx->data;
			int offset = ipip_pkt_size - 256 - 320 - data_len;

			ctx_adjust_troom(ctx, offset);

			void *data = (void *)(long)ctx->data;
			void *data_end = (void *)(long)ctx->data_end;

			if (data + ipip_pkt_size > data_end)
				test_fatal("ipip packet too large");

			memcpy(data, pkt, ipip_pkt_size);
		}

		// 2. Run the conntrack lookup
		struct ipv4_ct_tuple tuple = {};
		void *data;
		void *data_end;
		struct iphdr *ip4;
		int l3_off = ETH_HLEN;
		int l4_off;
		struct ct_state ct_state = {};
		struct ct_state ct_new = {};
		__u16 proto;
		__u32 monitor = 0;
		int ret;

		bpf_clear_meta(ctx);
		assert(validate_ethertype(ctx, &proto));
		assert(revalidate_data(ctx, &data, &data_end, &ip4));

		tuple.nexthdr = ip4->protocol;
		tuple.daddr = ip4->daddr;
		tuple.saddr = ip4->saddr;
		l4_off = l3_off + ipv4_hdrlen(ip4);

		// Check that the protocol is correct
		assert(tuple.nexthdr == IPPROTO_IPIP);

		ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, ip4, l4_off,
					CT_EGRESS, &ct_state, &monitor);

	// 3. Assert that it's treated as a new connection
		switch (ret) {
		case CT_NEW:
			ct_new.node_port = ct_state.node_port;
			ct_new.ifindex = ct_state.ifindex;
			ret = ct_create4(get_ct_map4(&tuple), &CT_MAP_ANY4, &tuple, ctx,
						CT_EGRESS, &ct_new, NULL);
			break;

		default:
			test_log("ct_lookup4 for ipip, expected CT_NEW, got %d", ret);
			test_fail();
		}

	// 4. Verify the entry was created in the conntrack map
		struct ct_entry *entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

		assert(entry); // Fails if entry was not created

		// We don't check TCP flags here, as it's not a TCP packet
	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
