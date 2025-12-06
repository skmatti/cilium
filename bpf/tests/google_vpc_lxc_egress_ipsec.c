/* FLAGS UNDER TEST */
#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_GOOGLE_GENEVE
#define ENCAP_IFINDEX 4
#define ENABLE_GOOGLE_VPC
#define ENABLE_HOST_FIREWALL

#define ENABLE_EGRESS_GATEWAY
#define ENABLE_EGRESS_GATEWAY_COMMON
#define TUNNEL_MODE
#define ENABLE_ROUTING

// Test with software IPsec
#define GOOGLE_IPSEC_MODE 1

#include "common.h"

#include <bpf/ctx/skb.h>

#include "google_vpc_lxc_egress_common.h"
