#ifndef __GOOGLE_MAPS_H_
#define __GOOGLE_MAPS_H_

#include <bpf/api.h>

#include "common.h"
#include "google_nsh.h"

struct multi_nic_dev_key {
	__u8 mac[6];
};

struct multi_nic_dev_info {
	__u32 ifindex;
	__u16 ep_id;
	__u32 net_id;
};

struct sfc_select_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16	ep_id;
	__u8	family;
	__u8	is_egress:1, /* 0: ingress, 1: egress */
		pad0:7;
	__be16	port; /* network order */
	__u8	protocol;
	__u8    pad1;
	union {
		struct {
			__u32 ip4;
			__u32 pad2;
			__u32 pad3;
			__u32 pad4;
		};
		union v6addr ip6;
	};
} __packed;

struct sfc_select_entry {
	__u8	prefix_len;
	__u8	pad0;
	__u16	pad1;
	/* Not using bitfields because memory layout is under-specified; network order */
	nshpath path;
} __packed;

struct sfc_path_key {
	/* Not using bitfields because memory layout is under-specified; network order */
	nshpath path;
};

struct sfc_path_entry {
	/* Service function IPv4 address */
	__be32 address;
};

struct sfc_ipv4_flow_key {
	/* These field names are correct for original direction traffic.
	 * All are stored in network order, except `ep_id`.
	 */
	__be32		saddr;
	__be32		daddr;
	__be16		sport;
	__be16		dport;
	__u16		ep_id;
	__u8		nexthdr;
	__u8		pad;
} __packed;

struct sfc_ipv4_flow_entry {
	/* SPI/SI encoded */
	nshpath path;
	/* The IP of the previous hop in the chain in the forward direction. */
	__be32 previous_hop_addr;

	__u32 lifetime;  // The time when this entry expires.

	// Flags related to current TCP state.
	// tx maps to forwarding path from source to destination.
	// rx maps to returning path from destination to source.
	__u16 rx_closing:1,  // The TCP is closing on the rx direction.
	      tx_closing:1,  // The TCP is closing on the tx direction.
	      seen_non_syn:1,  // The TCP has seen non syn packet.
	      seen_rx_syn:1,  // The TCP has seen syn on the rx direction.
	      seen_tx_syn:1,  // The TCP has seen syn on the tx direction.
	      reserved:11;
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

#ifdef ENABLE_GOOGLE_SERVICE_STEERING

/* Service steering maps:
 * - SFC_SELECT_MAP (ep_id, flags, port, proto, cidr) -> (prefix_len, spi, si)
 * - SFC_PATH_MAP   (spi, si) -> (sf_ip)
 * - SFC_FLOW_MAP   5-tuple -> (spi, si, previous_hop_ip) + connection tracking
 */

#ifndef SFC_SELECT_MAP_SIZE
#define SFC_SELECT_MAP_SIZE 16384
#endif
#ifndef SFC_PATH_MAP_SIZE
#define SFC_PATH_MAP_SIZE 16384
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct sfc_select_key);
	__type(value, struct sfc_select_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SFC_SELECT_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} SFC_SELECT_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sfc_path_key);
	__type(value, struct sfc_path_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SFC_PATH_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} SFC_PATH_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct sfc_ipv4_flow_key);
	__type(value, struct sfc_ipv4_flow_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, CT_MAP_SIZE_TCP);  // reuse CT_MAP_SIZE_TCP
} SFC_FLOW_MAP_ANY4 __section_maps_btf;

#endif /* ENABLE_GOOGLE_SERVICE_STEERING */

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

#endif // __GOOGLE_MAPS_H_
