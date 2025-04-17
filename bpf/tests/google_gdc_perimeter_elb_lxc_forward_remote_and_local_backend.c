#include <bpf/ctx/skb.h>
#include "common.h"
#include "lib/endian.h"
#include "pktgen.h"

/* Set ETH_HLEN to 14 to indicate that the packet has a 14 byte ethernet header
 */
#define ETH_HLEN 14
#define HAVE_LPM_TRIE_MAP_TYPE
/* Enable code paths under test */
#define ENABLE_IPV4
#define NOT_VTEP_DST  0
#define ENCAP_IFINDEX 42
#define DISABLE_SIP_VERIFICATION
#define ENABLE_GOOGLE_GENEVE
#define ENABLE_GOOGLE_VPC
#define ENABLE_DSR
#define DSR_ENCAP_IPIP	 2
#define DSR_ENCAP_GENEVE 3
#define DSR_ENCAP_MODE	 DSR_ENCAP_GENEVE
#define ENABLE_NODEPORT
#define NATIVE_DEV_IFINDEX 0
#define TUNNEL_MODE
#define ENABLE_ROUTING 1
#define CLIENT_IP	    v4_ext_one
#define CLIENT_PORT	    __bpf_htons(111)
#define FRONTEND_IP	    v4_svc_two
#define FRONTEND_PORT	    tcp_svc_one
#define LB_IP		    v4_node_one
#define IPV4_DIRECT_ROUTING 222
#define BACKEND_IP	    v4_pod_one
#define BACKEND_PORT	    __bpf_htons(8080)
#define BACKEND_VM_IP	    v4_node_one
#define BACKEND_NODE_IP	    v4_node_two
#define DEST_IFINDEX	    5
#define DEST_LXC_ID	    200

#define HAVE_FIB_NEIGH	    1

#define ENABLE_EGRESS_GATEWAY
#define ENABLE_EGRESS_GATEWAY_COMMON

/* BOTH FLAGS TURNS ON PERIMETER ELB */
#define PERIMETER_ENDPOINT /* Only on perimeter node lxc interfaces */
#define ENABLE_EGRESS_GATEWAY_REDIRECT

static volatile const __u8 *client_mac = mac_one;
/* this matches the default node_config.h: */
static volatile const __u8 lb_mac[ETH_ALEN] = {
	0xce, 0x72, 0xa7, 0x03, 0x88, 0x56
};

#define SECCTX_FROM_IPCACHE 1

__section("mock-handle-policy")
int mock_handle_policy(struct __ctx_buff *ctx __maybe_unused)
{
	return TC_ACT_REDIRECT;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 256);
	__array(values, int());
} mock_policy_call_map __section(".maps") = {
    .values = {
		[DEST_LXC_ID] = &mock_handle_policy,
	},
};

#define tail_call_dynamic mock_tail_call_dynamic

static __always_inline __maybe_unused
void mock_tail_call_dynamic(struct __ctx_buff *ctx,
			    const void *map __maybe_unused,
			    __u32 slot __maybe_unused)
{
	tail_call(ctx, &mock_policy_call_map, slot);
}

#include <bpf_lxc.c>
#include "lib/encap.h"
#include "../lib/google/geneve.h"
#include "lib/lb.h"

#define FROM_CONTAINER 0

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(max_entries, 1);
	__array(values, int());
} entry_call_map __section(".maps") = {
    .values = {
		[FROM_CONTAINER] = &cil_from_container,
	},
};

#ifndef SKIP_POLICY_MAP
static __always_inline void add_allow_all_egress_policy(void)
{
	struct policy_key policy_key = {
		.egress = 1,
	};
	struct policy_entry policy_value = {
		.deny = 0,
	};
	map_update_elem(&POLICY_MAP, &policy_key, &policy_value, BPF_ANY);
}

static __always_inline void del_allow_all_egress_policy(void)
{
	struct policy_key policy_key = {
		.egress = 1,
	};
	map_delete_elem(&POLICY_MAP, &policy_key);
}
#endif

/*
 * Test geneve encapsulation for a service with existing remote backends for ELB from perimeter
 * gw node to backend pod. The packet should be geneve encapped at perimeter cluster and sent
 * with perimeter gw ip addr as geneve option so return traffic can be sent back to the
 * original perimeter gw node.
 * This test verifies the packet has correct geneve src, dst, and perimeter gateway option
 * set when leaving the perimeter gw node.
 */
PKTGEN("tc", "google_elb_encap_remote")
int google_elb_encap_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);

	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);

	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = BACKEND_IP;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);

	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = BACKEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "google_elb_encap_remote")
int google_elb_encap_setup(struct __ctx_buff *ctx)
{
	/* Avoid policy drop */
	add_allow_all_egress_policy();

	/* Add remote entry for backend pod */
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};

	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = BACKEND_VM_IP,
	};

	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* Add remote entry for backend VM hosting pod */
	struct ipcache_key node_cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_VM_IP,
	};

	struct remote_endpoint_info node_cache_value = {
		.sec_identity = 223344,
		.tunnel_endpoint = BACKEND_NODE_IP,
	};

	map_update_elem(&IPCACHE_MAP, &node_cache_key, &node_cache_value, BPF_ANY);

	{
		const __be32 remote_node_ip = BACKEND_NODE_IP;
		const __u8 remote_mac[] = { 0x13, 0x37, 0x13, 0x37, 0x13, 0x37 };

		map_update_elem(&NODEPORT_NEIGH4,
				&remote_node_ip, remote_mac, BPF_ANY);
	}

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_elb_encap_remote")
int google_elb_encap_check(__maybe_unused const struct __ctx_buff *ctx)
{
	test_init();
	struct geneve_perimeter_opt4 *gopt;
	struct ethhdr *l2;
	struct iphdr *l3, *inner_l3;
	struct tcphdr *tcp_inner;
	struct genevehdr *geneve;
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *udp;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;

	if (*status_code != CTX_ACT_REDIRECT) {
		test_fatal("expected status code to be CTX_ACT_REDIRECT ('%d') but got '%d'",
			   CTX_ACT_REDIRECT, *status_code);
	}

	l2 = data + sizeof(__u32);

	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("outer l2 out of bounds");

	l3 = (void *)l2 + sizeof(*l2);

	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("outer l3 out of bounds");

	udp = (void *)l3 + sizeof(*l3);
	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("udp out of bounds");

	geneve = (void *)udp + sizeof(*udp);
	if ((void *)geneve + sizeof(*geneve) > data_end)
		test_fatal("geneve out of bounds");

	gopt = (void *)geneve + sizeof(*geneve);

	if ((void *)gopt + sizeof(*gopt) > data_end)
		test_fatal("gopt out of bounds");

	if ((void *)gopt + geneve->opt_len * 4 > data_end)
		test_fatal("geneve opts out of bounds");

	inner_l3 = (void *)gopt + geneve->opt_len * 4;

	if ((void *)inner_l3 + sizeof(*inner_l3) > data_end)
		test_fatal("inner l3 out of bounds");

	tcp_inner = (void *)inner_l3 + sizeof(*inner_l3);

	if ((void *)tcp_inner + sizeof(*tcp_inner) > data_end)
		test_fatal("tcp out of bounds");

	if (geneve->opt_len * 4 != sizeof(*gopt)) {
		int geneve_opt_len = (geneve->opt_len * 4);
		test_fatal("geneve has unexpected opt length: %d", geneve_opt_len);
	}

	if (gopt->hdr.opt_class != bpf_htons(GOOGLE_GENEVE_OPT_CLASS))
		test_fatal("geneve opt has unexpected class ('%d')",
			   gopt->hdr.opt_class);

	if (gopt->hdr.type != PERIMETER_GENEVE_INGRESS_OPT_TYPE)
		test_fatal("geneve opt has unexpected type");

	if (gopt->hdr.length != PERIMETER_IPV4_GENEVE_OPT_LEN)
		test_fatal("geneve opt has unexpected length");

	if (gopt->addr != LXC_IPV4)
		test_fatal("geneve opt has unexpected perimeter gateway node IP");

	/* Delete remote endpoint from the IPCACHE_MAP*/
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};

	map_delete_elem(&IPCACHE_MAP, &cache_key);

	del_allow_all_egress_policy();

	test_finish();
}

/* Verify local delivery for a ELB service with existing local backends. */
PKTGEN("tc", "google_elb_local")
int google_elb_local_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct tcphdr *l4;
	struct ethhdr *l2;
	struct iphdr *l3;
	void *data;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Push ethernet header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;
	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* Push IPv4 header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;
	l3->saddr = CLIENT_IP;
	l3->daddr = BACKEND_IP;

	/* Push TCP header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;
	l4->source = CLIENT_PORT;
	l4->dest = BACKEND_PORT;

	data = pktgen__push_data(&builder, default_data, sizeof(default_data));

	if (!data)
		return TEST_ERROR;

	/* Calc lengths, set protocol fields and calc checksums */
	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "google_elb_local")
int google_elb_local_setup(struct __ctx_buff *ctx)
{
	/* Avoid policy drop */
	add_allow_all_egress_policy();

	/* Add remote entry for backend pod */
	struct ipcache_key cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};

	struct remote_endpoint_info cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = BACKEND_VM_IP,
		.flag_skip_tunnel = true,
	};

	map_update_elem(&IPCACHE_MAP, &cache_key, &cache_value, BPF_ANY);

	/* Add local endpoint to the ENDPOINTS_MAP */
	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};

	struct endpoint_info ep_value = {
		.ifindex = DEST_IFINDEX,
		.lxc_id = DEST_LXC_ID,
	};

	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	/*Add perimeter gateway node to GOOGLE_REDIRECT_EP_ID_V4_MAP*/
	struct ipv4_redirect_ep redirect_ep_key = {
		.ip4 = LXC_IPV4,
	};

	__u16 endpoint_id = 1;

	map_update_elem(&GOOGLE_REDIRECT_EP_ID_V4_MAP, &redirect_ep_key,
			&endpoint_id, BPF_ANY);

	/* Jump into the entrypoint */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	/* Fail if we didn't jump */
	return TEST_ERROR;
}

CHECK("tc", "google_elb_local")
int google_elb_local_check(__maybe_unused const struct __ctx_buff *ctx)
{
	test_init();
	void *data, *data_end;
	__u32 *status_code;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	status_code = data;
	if (*status_code != CTX_ACT_REDIRECT) {
		test_fatal("expected status code to be CTX_ACT_REDIRECT ('%d') but got '%d'",
			   CTX_ACT_REDIRECT, *status_code);
	}

	/* Check that the packet gets routed to the destination interface */
	if (ctx_load_meta(ctx, CB_IFINDEX) != DEST_IFINDEX)
		test_fatal("expected interface '%d' but got '%d' instead",
			   DEST_IFINDEX, ctx->ingress_ifindex);

	/* Clean Up */
	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};

	map_delete_elem(&ENDPOINTS_MAP, &ep_key);

	struct ipv4_redirect_ep redirect_ep_key = {
		.ip4 = LXC_IPV4,
	};

	map_delete_elem(&GOOGLE_REDIRECT_EP_ID_V4_MAP, &redirect_ep_key);

	del_allow_all_egress_policy();

	test_finish();
}

PKTGEN("tc", "google_elb_remote_backend_running_on_local_vm")
int google_remote_backend_local_vm_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	struct ethhdr *l2;
	struct iphdr *l3;
	struct tcphdr *l4;

	/* Init packet builder */
	pktgen__init(&builder, ctx);

	/* Ethernet Header */
	l2 = pktgen__push_ethhdr(&builder);
	if (!l2)
		return TEST_ERROR;

	ethhdr__set_macs(l2, (__u8 *)client_mac, (__u8 *)lb_mac);

	/* IPv4 Header */
	l3 = pktgen__push_default_iphdr(&builder);
	if (!l3)
		return TEST_ERROR;

	l3->saddr = CLIENT_IP;
	l3->daddr = BACKEND_IP;

	/* TCP Header */
	l4 = pktgen__push_default_tcphdr(&builder);
	if (!l4)
		return TEST_ERROR;

	l4->source = CLIENT_PORT;
	l4->dest = BACKEND_PORT;

	pktgen__finish(&builder);

	return 0;
}

SETUP("tc", "google_elb_remote_backend_running_on_local_vm")
int google_remote_backend_local_vm_case_setup(const struct __ctx_buff *ctx)
{
	/* Avoid policy drop */
	add_allow_all_egress_policy();
	/* Add Backend IP to IP Cache map */
	struct ipcache_key ip_cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};
	struct remote_endpoint_info ip_cache_value = {
		.sec_identity = 112233,
		.tunnel_endpoint = BACKEND_VM_IP,
	};

	map_update_elem(&IPCACHE_MAP, &ip_cache_key, &ip_cache_value, BPF_ANY);

	/* Add Backend VM IP to endpoint map */
	struct ipcache_key vm_ip_cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_VM_IP,
	};
	struct remote_endpoint_info vm_ip_cache_value = {
		.sec_identity = 112244,
		.tunnel_endpoint = IPV4(0, 0, 0, 0),
	};

	map_update_elem(&IPCACHE_MAP,
			&vm_ip_cache_key, &vm_ip_cache_value, BPF_ANY);

	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_VM_IP,
	};
	struct endpoint_info ep_value = {
		.ifindex = DEST_IFINDEX,
		.lxc_id = DEST_LXC_ID,
	};

	map_update_elem(&ENDPOINTS_MAP, &ep_key, &ep_value, BPF_ANY);

	/* Add perimeter gateway node to GOOGLE_REDIRECT_EP_ID_V4_MAP */
	struct ipv4_redirect_ep redirect_ep_key = {
		.ip4 = LXC_IPV4,
	};
	__u16 endpoint_id = 1;

	map_update_elem(&GOOGLE_REDIRECT_EP_ID_V4_MAP, &redirect_ep_key,
			&endpoint_id, BPF_ANY);

	/* Jump to Entry Point */
	tail_call_static(ctx, entry_call_map, FROM_CONTAINER);

	return TEST_ERROR;
}

CHECK("tc", "google_elb_remote_backend_running_on_local_vm")
int google_remote_backend_local_vm_case_check(const struct __ctx_buff *ctx)
{
	test_init();
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");

	__u32 *status_code = data;

	if (*status_code != CTX_ACT_REDIRECT) {
		test_fatal("expected CTX_ACT_REDIRECT ('%d') but got '%d'",
			   CTX_ACT_REDIRECT, *status_code);
	}

	/*
	 * Check that the IFINDEX slot in the packets meta data has been set to the
	 * destination interface
	 */
	if (ctx_load_meta(ctx, CB_IFINDEX) != DEST_IFINDEX)
		test_fatal("expected interface '%d' got '%d' instead",
			   DEST_IFINDEX, ctx->ingress_ifindex);

	/* Clean Up */
	struct ipcache_key ip_cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_IP,
	};

	map_delete_elem(&IPCACHE_MAP, &ip_cache_key);

	struct ipcache_key vm_ip_cache_key = {
		.lpm_key.prefixlen = IPCACHE_PREFIX_LEN(32),
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_VM_IP,
	};

	map_delete_elem(&IPCACHE_MAP, &vm_ip_cache_key);

	struct endpoint_key ep_key = {
		.family = ENDPOINT_KEY_IPV4,
		.ip4 = BACKEND_VM_IP,
	};

	map_delete_elem(&ENDPOINTS_MAP, &ep_key);

	del_allow_all_egress_policy();

	test_finish();
}
