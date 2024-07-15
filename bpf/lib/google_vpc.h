#ifndef __LIB_GOOGLE_VPC_H_
#define __LIB_GOOGLE_VPC_H_

#ifdef ENABLE_GOOGLE_VPC

#include "eps.h"
#include "l3.h"

/*
 * nested_remote_endpoint_v4 performs a nested lookup for the remote endpoint and
 * overrides the incoming pointer values.
 * Each call to this function resolves to the next parent layer for the endpoint.
 * In a deployment mode with only a single nested layer, this lookup resolves to
 * the infrastructure for the remote endpoint.
 */
static __always_inline int
nested_remote_endpoint_v4(__u32 *tunnel_endpoint, __u32 *dst_sec_identity, __u8 *encrypt_key)
{
	struct remote_endpoint_info *infra_info;

	infra_info = lookup_ip4_remote_endpoint(*tunnel_endpoint);
	if (!infra_info) {
		// We should always have an entry in the infra-cluster.
		// This will either map to an infra-cluster endpoint (e.g. L3 VM multi-nic), or;
		// to an infra-cluster node (if the src in an infra-cluster pod).
		return DROP_NO_TUNNEL_ENDPOINT;
	}
	if (identity_is_node(infra_info->sec_label)) {
		/*
		 * If the remote endpoint is already a node, it means this packet is going
		 * to a infra-cluster pod. In this case we should not update the tunnel_endpoint to
		 * infra_info->tunnel_endpoint, which will likely be 0.
		 */
		return CTX_ACT_OK;
	}
	// This is only used for a send_notify.
	*dst_sec_identity = infra_info->sec_label;
	// This is the critical information for the tunnel addressing.
	*tunnel_endpoint = infra_info->tunnel_endpoint;
	// TODO: determine whether this is relevant.
	*encrypt_key = get_min_encrypt_key(infra_info->key);

	return CTX_ACT_OK;
}

// Sets correct identity when Google VPC is enabled.
void set_gooogle_vpc_identity(__u32 *identity, struct remote_endpoint_info *info)
{
	if (info)
		*identity = info->sec_label;
}

#endif /* ENABLE_GOOGLE_VPC */

#endif /* __LIB_GOOGLE_VPC_H_ */
