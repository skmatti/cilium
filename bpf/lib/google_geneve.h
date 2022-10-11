#ifndef __LIB_GOOGLE_GENEVE_H_
#define __LIB_GOOGLE_GENEVE_H_

#include "common.h"

#define GENEVE_VERSION 0

/* Geneve Header:
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Virtual Network Identifier (VNI)       |    Reserved   |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                    Variable Length Options                    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct genevehdr {
#ifdef __LITTLE_ENDIAN_BITFIELD
	__u8 opt_len:6;
	__u8 ver:2;
	__u8 r1:6;
	__u8 critical:1;
	__u8 control:1;
#else
	__u8 ver:2;
	__u8 opt_len:6;
	__u8 control:1;
	__u8 critical:1;
	__u8 r1:6;
#endif
	__be16 protocol;
	__u8 vni[3];
	__u8 r2;
	/* Options not yet supported */
};

static __always_inline void geneve_init(struct genevehdr *hdr, __u16 protocol) {
    *hdr = (const struct genevehdr){
		.ver = GENEVE_VERSION,
		.protocol = bpf_htons(protocol),
	};
}

static __always_inline __u16 geneve_protocol(const struct genevehdr *hdr) {
    return bpf_ntohs(hdr->protocol);
}

#endif /* __LIB_GOOGLE_GENEVE_H_ */
