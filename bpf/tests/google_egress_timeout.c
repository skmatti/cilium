#define HAVE_LPM_TRIE_MAP_TYPE
#include "common.h"

#include <bpf/ctx/skb.h>
#include "pktgen.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header */
#define ETH_HLEN 14

/* Enable code paths under test */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY
#define ENABLE_MASQUERADE_IPV4
#define ENCAP_IFINDEX		42
#define SECONDARY_IFACE_IFINDEX 44

#define SECCTX_FROM_IPCACHE	1

#define ctx_redirect		mock_ctx_redirect
static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused);

#define fib_lookup mock_fib_lookup
static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused);

#include "bpf_host.c"

#include "lib/egressgw.h"
#include "lib/ipcache.h"

#include "lib/google_maps.h"
#include "lib/google_egress_gw.h"

static __always_inline __maybe_unused int
mock_ctx_redirect(const struct __sk_buff *ctx __maybe_unused,
		  int ifindex __maybe_unused, __u32 flags __maybe_unused)
{
	if (ifindex == ENCAP_IFINDEX)
		return CTX_ACT_REDIRECT;
	if (ifindex == SECONDARY_IFACE_IFINDEX)
		return CTX_ACT_REDIRECT;

	return CTX_ACT_DROP;
}

static __always_inline __maybe_unused long
mock_fib_lookup(void *ctx __maybe_unused, struct bpf_fib_lookup *params __maybe_unused,
		int plen __maybe_unused, __u32 flags __maybe_unused)
{
	if (params && params->ipv4_src == EGRESS_IP2)
		params->ifindex = SECONDARY_IFACE_IFINDEX;

	return 0;
}

#define TO_NETDEV   0
#define FROM_NETDEV 1

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 2);
	__array(values, int());
} entry_call_map __section(".maps") = {
	.values = {
		[TO_NETDEV] = &cil_to_netdev,
		[FROM_NETDEV] = &cil_from_netdev,
	},
};

const struct connection_timeouts ct_timeouts = {
	.bpf_ct_timeout_regular_any = 1000,
	.bpf_ct_timeout_regular_tcp = 2000,
	.bpf_ct_timeout_regular_tcp_fin = 3000,
	.bpf_ct_timeout_regular_tcp_syn = 4000,
};

/* Tests SYN packet to EXTERNAL_IP with matching EGRESS_TIMEOUTS_ENTRY, */
/* expecting new CT entry with bpf_ct_timeout_regular_tcp_syn lifetime. */
PKTGEN("tc", "google_egress_timeout_tcp_syn")
int egressgw_timeout_tcp_syn_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx){
				       .test = TEST_SNAT1,
			       });
}

SETUP("tc", "google_egress_timeout_tcp_syn")
int egressgw_timeout_tcp_syn_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24,
				  GATEWAY_NODE_IP, EGRESS_IP);
	add_egressgw_timeout_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, ct_timeouts);

	/* Jump into the entrypoint */
	set_identity_mark(ctx, CLIENT_IDENTITY, MARK_MAGIC_EGW_DONE);
	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_egress_timeout_tcp_syn")
int egressgw_timeout_tcp_syn_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	__u32 syn_timeout = 4000;
	struct ipv4_ct_tuple tuple = {
		.daddr = CLIENT_IP,
		.saddr = EXTERNAL_SVC_IP,
		.dport = EXTERNAL_SVC_PORT,
		.sport = client_port(TEST_SNAT1),
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};
	__u32 now = bpf_mono_now();

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	if (ct_entry->lifetime - now != syn_timeout)
		test_error("bad ct lifetime (expected %u, actual %u)", syn_timeout,
			   ct_entry->lifetime - now);

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx){
						.status_code = TC_ACT_OK,
					});
	if (ret != TEST_PASS)
		test_error("got status, expected status", ret, TC_ACT_OK);

	test_finish();
}

/* Tests SYN packet to EXTERNAL_IP with matching EGRESS_TIMEOUTS_ENTRY and existing CT, */
/* expecting CT lifetime update to bpf_ct_timeout_regular_tcp_syn */
PKTGEN("tc", "google_egress_timeout_ct_lookup")
int egressgw_timeout_ct_lookup_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx){
				       .test = TEST_SNAT1,
			       });
}

SETUP("tc", "google_egress_timeout_ct_lookup")
int egressgw_timeout_ct_lookup_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24,
				  GATEWAY_NODE_IP, EGRESS_IP);
	add_egressgw_timeout_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, ct_timeouts);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "google_egress_timeout_ct_lookup")
int egressgw_timeout_ct_lookup_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();
	__u32 syn_timeout = 4000;
	struct ipv4_ct_tuple tuple = {
		.daddr = CLIENT_IP,
		.saddr = EXTERNAL_SVC_IP,
		.dport = EXTERNAL_SVC_PORT,
		.sport = client_port(TEST_SNAT1),
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};
	__u32 now = bpf_mono_now();

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	if (ct_entry->lifetime - now != syn_timeout)
		test_error("bad ct lifetime (expected %u, actual %u)", syn_timeout,
			   ct_entry->lifetime - now);

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx){
						.status_code = TC_ACT_OK,
					});
	if (ret != TEST_PASS)
		test_error("got status, expected status", ret, TC_ACT_OK);

	test_finish();
}

/* Tests non-SYN TCP packet to EXTERNAL_IP with matching EGRESS_TIMEOUTS_ENTRY and existing CT, */
/* expecting CT lifetime update to bpf_ct_timeout_regular_tcp */
PKTGEN("tc", "google_egress_timeout_tcp_regular")
int egressgw_timeout_ct_tcp_regular_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx){
				       .test = TEST_SNAT1,
				       .l4_ack = 1,
			       });
}

SETUP("tc", "google_egress_timeout_tcp_regular")
int egressgw_timeout_tcp_regular_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24,
				  GATEWAY_NODE_IP, EGRESS_IP);
	add_egressgw_timeout_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, ct_timeouts);

	struct ipv4_ct_tuple tuple = {
		.daddr = CLIENT_IP,
		.saddr = EXTERNAL_SVC_IP,
		.dport = EXTERNAL_SVC_PORT,
		.sport = client_port(TEST_SNAT1),
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = NULL;

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!ct_entry)
		return TEST_ERROR;

	ct_entry->seen_non_syn = 1;
	ct_entry->rx_closing = 0;
	ct_entry->tx_closing = 0;
	map_update_elem(get_ct_map4(&tuple), &tuple, ct_entry, BPF_ANY);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "google_egress_timeout_tcp_regular")
int egressgw_timeout_tcp_regular_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();
	__u32 tcp_regular_timeout = 2000;
	struct ipv4_ct_tuple tuple = {
		.daddr = CLIENT_IP,
		.saddr = EXTERNAL_SVC_IP,
		.dport = EXTERNAL_SVC_PORT,
		.sport = client_port(TEST_SNAT1),
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	if (ct_entry->seen_non_syn != 1)
		test_error("expected seen_non_syn to be 1 (got %u)", ct_entry->seen_non_syn);

	__u32 now = bpf_mono_now();

	if (ct_entry->lifetime - now != tcp_regular_timeout)
		test_error("bad ct lifetime (expected %u, actual %u)", tcp_regular_timeout,
			   ct_entry->lifetime - now);

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx){
						.status_code = TC_ACT_OK,
					});
	if (ret != TEST_PASS)
		test_error("got status, expected status", ret, TC_ACT_OK);

	test_finish();
}

/* Tests reply TCP packet to CLIENT_IP with matching EGRESS_TIMEOUTS_ENTRY and existing CT, */
/* expecting CT lifetime update to bpf_ct_timeout_regular_tcp */
PKTGEN("tc", "google_egress_timeout_tcp_regular_reply")
int egressgw_timeout_tcp_reply_regular_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx){
				       .test = TEST_SNAT1,
				       .dir = CT_INGRESS,
			       });
}

SETUP("tc", "google_egress_timeout_tcp_regular_reply")
int egressgw_timeout_tcp_reply_regular_setup(struct __ctx_buff *ctx)
{
	/* install ipcache entry for the CLIENT_IP: */
	ipcache_v4_add_entry(CLIENT_IP, 0, 0, CLIENT_NODE_IP, 0);

	struct ipv4_ct_tuple tuple = {
		.daddr = CLIENT_IP,
		.saddr = EXTERNAL_SVC_IP,
		.dport = EXTERNAL_SVC_PORT,
		.sport = client_port(TEST_SNAT1),
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = NULL;

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		return TEST_ERROR;

	ct_entry->seen_non_syn = 1;
	ct_entry->rx_closing = 0;
	ct_entry->tx_closing = 0;
	map_update_elem(get_ct_map4(&tuple), &tuple, ct_entry, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_NETDEV);
	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_egress_timeout_tcp_regular_reply")
int egressgw_timeout_tcp_reply_regular_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();
	__u32 tcp_regular_timeout = 2000;
	struct ipv4_ct_tuple tuple = {
		.daddr = CLIENT_IP,
		.saddr = EXTERNAL_SVC_IP,
		.dport = EXTERNAL_SVC_PORT,
		.sport = client_port(TEST_SNAT1),
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	__u32 now = bpf_mono_now();

	if (ct_entry->lifetime - now != tcp_regular_timeout)
		test_error("bad ct lifetime (expected %u, actual %u)", tcp_regular_timeout,
			   ct_entry->lifetime - now);

	int ret = egressgw_status_check(ctx,
			 (struct egressgw_test_ctx){
			     .status_code = CTX_ACT_REDIRECT,
		     });
	if (ret != TEST_PASS)
		test_error("got status, expected status", ret, CTX_ACT_REDIRECT);

	map_delete_elem(get_ct_map4(&tuple), &tuple);
	test_finish();
}

/* Tests FIN packet to EXTERNAL_IP with matching EGRESS_TIMEOUTS_ENTRY and existing CT */
/* expecting CT lifetime update to bpf_ct_timeout_regular_tcp_fin */
PKTGEN("tc", "google_egress_timeout_tcp_fin")
int egressgw_timeout_ct_tcp_fin_pktgen(struct __ctx_buff *ctx)
{
	return egressgw_pktgen(ctx, (struct egressgw_test_ctx){
				       .test = TEST_SNAT1,
				       .l4_fin = 1,
			       });
}

SETUP("tc", "google_egress_timeout_tcp_fin")
int egressgw_timeout_tcp_fin_setup(struct __ctx_buff *ctx)
{
	add_egressgw_policy_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24,
				  GATEWAY_NODE_IP, EGRESS_IP);
	add_egressgw_timeout_entry(CLIENT_IP, EXTERNAL_SVC_IP & 0xffffff, 24, ct_timeouts);

	struct ipv4_ct_tuple tuple = {
		.daddr = CLIENT_IP,
		.saddr = EXTERNAL_SVC_IP,
		.dport = EXTERNAL_SVC_PORT,
		.sport = client_port(TEST_SNAT1),
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_entry *ct_entry = NULL;

	ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		return TEST_ERROR;

	ct_entry->seen_non_syn = 1;
	ct_entry->rx_closing = 1;
	ct_entry->tx_closing = 1;
	map_update_elem(get_ct_map4(&tuple), &tuple, ct_entry, BPF_ANY);

	tail_call_static(ctx, entry_call_map, TO_NETDEV);
	return TEST_ERROR;
}

CHECK("tc", "google_egress_timeout_tcp_fin")
int egressgw_timeout_tcp_fin_check(const struct __ctx_buff *ctx __maybe_unused)
{
	test_init();
	__u32 tcp_fin_timeout = 3000;
	struct ipv4_ct_tuple tuple = {
		.daddr = CLIENT_IP,
		.saddr = EXTERNAL_SVC_IP,
		.dport = EXTERNAL_SVC_PORT,
		.sport = client_port(TEST_SNAT1),
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};
	__u32 now = bpf_mono_now();

	struct ct_entry *ct_entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);

	if (!ct_entry)
		test_fatal("no CT entry found");

	if (ct_entry->lifetime - now != tcp_fin_timeout)
		test_error("bad ct lifetime (expected %u, actual %u)", tcp_fin_timeout,
			   ct_entry->lifetime - now);

	int ret = egressgw_status_check(ctx, (struct egressgw_test_ctx){
						.status_code = TC_ACT_OK,
					});
	if (ret != TEST_PASS)
		test_error("got status, expected status", ret, TC_ACT_OK);

	test_finish();
}
