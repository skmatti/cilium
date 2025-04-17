#include "common.h"
#include "bpf/ctx/skb.h"
#include "tests/pktgen.h"

/* FLAGS UNDER TEST */
#define ENABLE_IPV4
#define GOOGLE_PERIMETER_FEATURES
#define ENABLE_NODEPORT
#define ENABLE_EGRESS_GATEWAY_REDIRECT
#define ENABLE_GOOGLE_GENEVE
#define ENCAP_IFINDEX 4
#define ENABLE_GOOGLE_VPC
#define ENABLE_HOST_FIREWALL
#define PERIMETER_ENDPOINT

#define ENABLE_EGRESS_GATEWAY
#define ENABLE_EGRESS_GATEWAY_COMMON

#define SECLABEL	   2222
#define SECLABEL_IPV4	   3333
#define LXC_IPV4	   10
#define NATIVE_DEV_IFINDEX 101

#include "node_config.h"
#include "lib/google_perimeter_elb.h"
#include "lib/google/pktgen.h"

CHECK("tc", "perimeter_unit_tests")
int perimeter_tests(struct __ctx_buff *ctx __maybe_unused)
{
	test_init();

	TEST("init_perimeter_ct_entry", {
		struct ipv4_ct_tuple new_tuple __maybe_unused = {};

		new_tuple.nexthdr = IPPROTO_TCP;
		new_tuple.daddr = v4_pod_one;
		new_tuple.saddr = v4_ext_one;
		new_tuple.dport = 4000;
		new_tuple.sport = 3000;

		__u16 endpoint_id = 42;

		int ret = google_perimeter__init_perimeter_ct_entry(ctx,
								    &new_tuple,
								    &endpoint_id);

		assert(!IS_ERR(ret));

		struct ct_entry *entry =
			map_lookup_elem(get_ct_map4(&new_tuple), &new_tuple);

		if (!entry)
			test_fatal("ct_entry was not found.");

		assert_num_equal(entry->rev_nat_index, endpoint_id);
		assert_num_equal(entry->dsr_internal, 1);

		assert_num_equal(entry->src_sec_id, WORLD_ID);
		assert_num_equal(entry->node_port, 1);

#ifdef HAVE_FIB_IFINDEX
		assert_num_equal(entry->ifindex, NATIVE_DEV_IFINDEX);
#endif
	});

	test_finish();
}

BPF_LICENSE("Dual BSD/GPL");
