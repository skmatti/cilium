#ifndef __LIB_GOOGLE_GENEVE_H_
#define __LIB_GOOGLE_GENEVE_H_

#include "common.h"

#define GENEVE_VERSION 0

static __always_inline void geneve_init(struct genevehdr *hdr, __u16 protocol) {
    *hdr = (const struct genevehdr){
		.ver = GENEVE_VERSION,
		.protocol_type = bpf_htons(protocol),
	};
}

static __always_inline __u16 geneve_protocol(const struct genevehdr *hdr) {
    return bpf_ntohs(hdr->protocol_type);
}

#endif /* __LIB_GOOGLE_GENEVE_H_ */
