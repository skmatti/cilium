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

struct sfc_cidr_key {
	struct bpf_lpm_trie_key lpm_key;
	__u16	ep_id;
	__u16	is_egress:1, /* 0: ingress, 1: egress */
		is_dst:1, /* 0: src_ip, 1: dst_ip */
		pad0:14;
	__u32	cidr;
} __packed;

struct sfc_cidr_entry {
	__u8	prefix_len;
} __packed;

struct sfc_select_key {
	__u16	ep_id;
	__be16	port; /* network order */
	__u32	src_cidr;
	__u32	dst_cidr;
	__u8	src_prefix_len;
	__u8	dst_prefix_len;
	__u8	protocol;
	__u8	is_egress:1, /* 0: ingress, 1: egress */
		pad0:7;
} __packed;

/* Structure representing an NSH service path header.
 * https://www.rfc-editor.org/rfc/rfc8300.html#section-2.3
 *
 * Service Path Identifier (SPI): 24 bits
 * Service Index (SI): 8 bits
 */
struct sfc_path_key {
	/* Not using bitfields because memory layout is under-specified; network order */
	nshpath path;
};

struct sfc_path_entry {
	/* Service function IPv4 address */
	__be32 address;
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
 * - SFC_CIDR_MAP   (ep_id, flags, cidr) -> (prefix_len)
 * - SFC_SELECT_MAP (ep_id, flags, src_cidr, dst_cidr, port, proto) -> (spi, si)
 * - SFC_PATH_MAP   (spi, si) -> (sf_ip)
 * - SFC_FLOW_MAP   5-tuple -> (spi, si, previous_hop_ip) + connection tracking
 */

#ifndef SFC_CIDR_MAP_SIZE
#define SFC_CIDR_MAP_SIZE 16384
#endif
#ifndef SFC_SELECT_MAP_SIZE
#define SFC_SELECT_MAP_SIZE 16384
#endif
#ifndef SFC_PATH_MAP_SIZE
#define SFC_PATH_MAP_SIZE 16384
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct sfc_cidr_key);
	__type(value, struct sfc_cidr_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SFC_CIDR_MAP_SIZE);
	__uint(map_flags, CONDITIONAL_PREALLOC);
} SFC_CIDR_MAP __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sfc_select_key);
	__type(value, struct sfc_path_key);
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

#endif /* ENABLE_GOOGLE_SERVICE_STEERING */

#endif // __GOOGLE_MAPS_H_
