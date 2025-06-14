#pragma once

#include "lib/common.h"

struct geneve_perimeter_opt4 {
	struct geneve_opt_hdr hdr;
	__be32	addr;
};

// Type = 0x3 (Special type for Perimeter Function)
# define PERIMETER_GENEVE_EGRESS_OPT_TYPE  (GENEVE_OPT_TYPE_CRIT | 0x03)
# define PERIMETER_GENEVE_INGRESS_OPT_TYPE (GENEVE_OPT_TYPE_CRIT | 0x04)

# define PERIMETER_IPV4_GENEVE_OPT_LEN \
	 GENEVE_OPT_LENGTH_FIELD(struct geneve_perimeter_opt4)
