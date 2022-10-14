#ifndef __LIB_GOOGLE_NSH_H_
#define __LIB_GOOGLE_NSH_H_

#include "common.h"

#define NSH_VERSION 0
#define ETH_P_NSH	0x894F

typedef unsigned int nshpath;

/*
 * Network Service Header:
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Ver|O|U|    TTL    |   Length  |U|U|U|U|MD Type| Next Protocol |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Service Path Identifier (SPI)        | Service Index |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * ~               Mandatory/Optional Context Headers              ~
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct nshhdr {
	__u32 base;
	nshpath path;
	/* Context headers not yet supported */
};

#define NSH_TTL_MASK        0x0fc00000
#define NSH_LEN_MASK        0x003f0000
#define NSH_MD_TYPE_MASK    0x00000f00
#define NSH_NEXT_PROT_MASK  0x000000ff
#define NSH_SPI_MASK        0xffffff00
#define NSH_SI_MASK         0x000000ff

#define NSH_TTL_SHIFT       22
#define NSH_LEN_SHIFT       16
#define NSH_MD_TYPE_SHIFT   8
#define NSH_NEXT_PROT_SHIFT 0
#define NSH_SPI_SHIFT       8
#define NSH_SI_SHIFT        0

#define NSH_NP_IPv4         0x1
#define NSH_NP_IPv6         0x2
#define NSH_DEFAULT_TTL     63

/* MD Type Registry. */
#define NSH_MD_TYPE_1       0x01
#define NSH_MD_TYPE_2       0x02

static __always_inline void nsh_init(struct nshhdr *hdr, nshpath path) {
	__u8 len = sizeof(struct nshhdr) >> 2;
	__u32 base =
		((NSH_DEFAULT_TTL << NSH_TTL_SHIFT)   & NSH_TTL_MASK) |
		((len << NSH_LEN_SHIFT)               & NSH_LEN_MASK) |
		((NSH_MD_TYPE_2 << NSH_MD_TYPE_SHIFT) & NSH_MD_TYPE_MASK) |
		((NSH_NP_IPv4 << NSH_NEXT_PROT_SHIFT) & NSH_NEXT_PROT_MASK);
	*hdr = (const struct nshhdr){
		.base = bpf_htonl(base),
		.path = path,
	};
}

static __always_inline nshpath nshpath_init(__u32 spi, __u8 si) {
	return bpf_htonl(
		((spi << NSH_SPI_SHIFT) & NSH_SPI_MASK) |
		((si << NSH_SI_SHIFT)   & NSH_SI_MASK)
	);
}

static __always_inline __u32 nshpath_spi(nshpath path) {
	return (bpf_ntohl(path) & NSH_SPI_MASK) >> NSH_SPI_SHIFT;
}

static __always_inline __u8 nshpath_si(nshpath path) {
	return (__u8)((bpf_ntohl(path) & NSH_SI_MASK) >> NSH_SI_SHIFT);
}

#endif /* __LIB_GOOGLE_NSH_H_ */
