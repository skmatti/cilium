#pragma once

#include <bpf/api.h>

#include "common.h"

struct multi_nic_dev_key {
	__u8 mac[6];
};

struct multi_nic_dev_info {
	__u32 ifindex;
	__u16 ep_id;
	__u16 pad;
	__u32 net_id;
};

struct host_dev_routing_key {
	struct bpf_lpm_trie_key lpm_key;
	__u32 if_index;
	__u8 family;
	__u8 pad0;
	__u16 pad1;
	union {
		struct {
			__u32 ip4;
			__u32 pad2;
			__u32 pad3;
			__u32 pad4;
		};
		union v6addr ip6;
	};
};

struct host_dev_routing_entry {
	union {
		struct {
			__u32 ip4;
			__u32 pad0;
			__u32 pad1;
			__u32 pad2;
		};
		union v6addr ip6;
	};
	__u8 family;
	__u8 pad3;
	__u16 pad4;
};

struct pip_cidr_key {
	struct bpf_lpm_trie_key lpm_key;
	__u8 family;
	__u8 pad0;
	__u16 pad1;
	union {
		struct {
			__u32 ip4;
			__u32 pad2;
			__u32 pad3;
			__u32 pad4;
		};
		union v6addr ip6;
	};
};

struct pip_routing_entry {
	union {
		struct {
			__u32 ip4;
			__u32 pad0;
			__u32 pad1;
			__u32 pad2;
		};
		union v6addr ip6;
	};
	__u8 family;
	__u8 pad3;
	__u16 pad4;
};

struct ipv4_redirect_ep {
	/* Perimeter Node IP address */
	__u32 ip4;
} __packed;

/*
 * connection_timeouts - Per-endpoint connection timeouts for egress NAT.
 *
 * This struct defines custom timeout values for different connection states
 * in egress NAT scenarios.  These timeouts are stored in the
 * EGRESS_POLICY_TIMEOUTS_MAP, which is keyed by the source endpoint.
 *
 * EGRESS_POLICY_TIMEOUTS_MAP is a subset of EGRESS_POLICY_MAP, and
 * only contains entries for endpoints whose corresponding
 * CiliumEgressGatewayPolicy defines custom timeouts. If a timeout
 * value is not specified for a given endpoint, or if there is no
 * corresponding entry in EGRESS_POLICY_TIMEOUTS_MAP for the endpoint,
 * the default timeout value from cilium-config will be used.
 */
struct connection_timeouts {
	__u32 bpf_ct_timeout_regular_any;
	__u32 bpf_ct_timeout_regular_tcp;
	__u32 bpf_ct_timeout_regular_tcp_fin;
	__u32 bpf_ct_timeout_regular_tcp_syn;
};

struct egress_gw_timeouts_entry {
	struct connection_timeouts egress_connection_timeouts;
};

/* google_ctmap_entry holds 1 IPv4 field and support up to 16
 *  flags which help determine the context of the IP address.
 *  Padding is reserved in the entry to account for future use cases.
 */
struct google_ctmap_entry {
	__u32 ip4_addr;
	__u32 egress_nat:1,
		  elb:1,
		  reserved:30;

};

#ifdef ENABLE_GOOGLE_MULTI_NIC

#ifndef MULTI_NIC_DEV_MAP_SIZE
#define MULTI_NIC_DEV_MAP_SIZE 16384
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct multi_nic_dev_key);
	__type(value, struct multi_nic_dev_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, MULTI_NIC_DEV_MAP_SIZE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} MULTI_NIC_DEV_MAP __section_maps_btf;

static __always_inline __maybe_unused struct multi_nic_dev_info *
lookup_multi_nic_dev(const union macaddr *mac)
{
	const struct multi_nic_dev_key *key =
	    (const struct multi_nic_dev_key *)mac;
	return map_lookup_elem(&MULTI_NIC_DEV_MAP, key);
}

#endif /* ENABLE_GOOGLE_MULTI_NIC */

#ifndef HOST_DEV_ROUTING_MAP_SIZE
#define HOST_DEV_ROUTING_MAP_SIZE 16384
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct host_dev_routing_key);
	__type(value, struct host_dev_routing_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, HOST_DEV_ROUTING_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} HOST_DEV_ROUTING_MAP __section_maps_btf;

/* HOST_DEV_ROUTING_STATIC_PREFIX gets sizeof non-IP, non-prefix part of host_dev_routing_key */
#define HOST_DEV_ROUTING_STATIC_PREFIX4							\
	(8 * (sizeof(struct host_dev_routing_key) - sizeof(struct bpf_lpm_trie_key)	\
	      - sizeof(union v6addr)))

#ifdef ENABLE_GOOGLE_PERSISTENT_IP

#ifndef PIP_ROUTING_MAP_SIZE
#define PIP_ROUTING_MAP_SIZE 16384
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct pip_cidr_key);
	__type(value, struct pip_routing_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, PIP_ROUTING_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} PIP_ROUTING_MAP __section_maps_btf;

#endif /* ENABLE_GOOGLE_PERSISTENT_IP */

#ifdef ENABLE_EGRESS_GATEWAY_REDIRECT

#ifndef GOOGLE_REDIRECT_EP_ID_V4_MAP
# define GOOGLE_REDIRECT_EP_ID_V4_MAP google_redirect_ep_id_v4
#endif

#ifndef GOOGLE_REDIRECT_EP_IP_V4_MAP
# define GOOGLE_REDIRECT_EP_IP_V4_MAP google_redirect_ep_ip_v4
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u16);
	__type(value, struct ipv4_redirect_ep);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 64);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} GOOGLE_REDIRECT_EP_IP_V4_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct ipv4_redirect_ep);
	__type(value, __u16);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 64);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} GOOGLE_REDIRECT_EP_ID_V4_MAP __section_maps_btf;

#endif /* ENABLE_EGRESS_GATEWAY_REDIRECT */

#ifdef ENABLE_EGRESS_GATEWAY
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct egress_gw_policy_key);
	__type(value, struct egress_gw_timeouts_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, EGRESS_POLICY_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} EGRESS_POLICY_TIMEOUTS_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct google_ctmap_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CT_MAP_SIZE_TCP + CT_MAP_SIZE_ANY);
} GOOGLE_CTMAP_V4 __section_maps_btf;
#endif /* ENABLE_EGRESS_GATEWAY */
