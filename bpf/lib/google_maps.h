#ifndef __GOOGLE_MAPS_H_
#define __GOOGLE_MAPS_H_

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

#endif /* ENABLE_GOOGLE_MULTI_NIC */
#endif // __GOOGLE_MAPS_H_
