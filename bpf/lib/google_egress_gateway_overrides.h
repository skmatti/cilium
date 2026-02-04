#pragma once

#if defined(GOOGLE_PERIMETER_FEATURES) && defined(ENABLE_EGRESS_GATEWAY_COMMON)

# define egress_gw_snat_needed_hook __skipped_egress_gw_snat_needed_hook

#include "lib/conntrack.h"
#include "lib/egress_gateway.h"
#include "lib/identity.h"

#undef egress_gw_snat_needed_hook

#ifndef GOOGLE_CLUSTER_ID
DEFINE_U32(GOOGLE_CLUSTER_ID, 0x10203040);
#define GOOGLE_CLUSTER_ID fetch_u32(GOOGLE_CLUSTER_ID)
#endif

static __always_inline bool google_is_local_cluster_identity(__u32 seclabel)
{
	__u32 cluster_id = (seclabel >> 16) & ((1 << 8) - 1);
	/* Parse cluster_id from destination identity and check if equal
	 * to local cluster_id
	 */
	if (cluster_id == GOOGLE_CLUSTER_ID)
		return true;
	return false;
}

static __always_inline bool
egress_gw_snat_needed_hook(__be32 saddr, __be32 daddr, __be32 *snat_addr)
{
	struct remote_endpoint_info *remote_ep =
		lookup_ip4_remote_endpoint(daddr, 0);

	/* If the packet is destined to an entity inside the cluster, either EP
	 * or node, skip SNAT since only traffic leaving the cluster is supposed
	 * to be masqueraded with an egress IP.
	 */
	if (remote_ep && identity_is_cluster(remote_ep->sec_identity)) {
		/* For local perimeter sources trying to reach remote eps, we skip EgressNAT
		 *
		 * If dest ep is not in perimeter cluster, this is org-internal ELB traffic
		 * and we should do EgressNAT (see: b/395925009)
		 */
		if (google_is_local_cluster_identity(remote_ep->sec_identity) ||
		    __lookup_ip4_endpoint(saddr))
			return false;
	}

	return egress_gw_snat_needed(saddr, daddr, snat_addr);
}

#endif /* GOOGLE_PERIMETER_FEATURES && ENABLE_EGRESS_GATEWAY_COMMON */
