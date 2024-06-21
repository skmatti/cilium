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
static __always_inline bool
nested_remote_endpoint_v4(__u32 *tunnel_endpoint, __u16 *dst_sec_identity, __u8 *encrypt_key)
{
	struct remote_endpoint_info *infra_info;

	infra_info = lookup_ip4_remote_endpoint(*tunnel_endpoint);
	if (!infra_info)
	{
		// We should always have an entry in the infra-cluster.
		// This will either map to an infra-cluster endpoint (e.g. L3 VM multi-nic), or;
		// to an infra-cluster node (if the src in an infra-cluster pod).
		return DROP_NO_TUNNEL_ENDPOINT;
	}
	// This is only used for a send_notify.
	*dst_sec_identity = infra_info->sec_label;
	// This is the critical information for the tunnel addressing.
	*tunnel_endpoint = infra_info->tunnel_endpoint;
	// TODO: determine whether this is relevant.
	*encrypt_key = get_min_encrypt_key(infra_info->key);

	return CTX_ACT_OK
}
#endif /* ENABLE_GOOGLE_VPC */