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

#endif // __GOOGLE_MAPS_H_
