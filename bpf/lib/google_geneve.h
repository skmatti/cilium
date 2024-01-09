#ifndef __LIB_GOOGLE_GENEVE_H_
#define __LIB_GOOGLE_GENEVE_H_

#include "common.h"

#define GENEVE_VERSION 0

// TODO: Allocate option class and type for service steering.
#define SFC_GENEVE_OPT_CLASS	0x0132
#define SFC_GENEVE_OPT_TYPE	(GENEVE_OPT_TYPE_CRIT | 0x02)
#define SFC_IPV4_GENEVE_OPT_LEN	\
	((sizeof(struct geneve_sfc_opt4) - sizeof(struct geneve_opt_hdr)) / 4)

struct geneve_sfc_opt4 {
	struct geneve_opt_hdr hdr;
	struct nshhdr nsh;
};

static __always_inline void sfc_geneve_init(struct genevehdr *hdr, struct geneve_sfc_opt4 *opt) {
    *hdr = (const struct genevehdr){
		.ver = GENEVE_VERSION,
		.protocol_type = bpf_htons(ETH_P_IP),
		.critical = 1,
		.opt_len= SFC_IPV4_GENEVE_OPT_LEN + 1,
	};
	opt->hdr = (const struct geneve_opt_hdr) {
		.opt_class = bpf_htons(SFC_GENEVE_OPT_CLASS),
		.type = SFC_GENEVE_OPT_TYPE,
		.length = SFC_IPV4_GENEVE_OPT_LEN,
	};
}

static __always_inline __u16 geneve_protocol(const struct genevehdr *hdr) {
    return bpf_ntohs(hdr->protocol_type);
}

#endif /* __LIB_GOOGLE_GENEVE_H_ */
