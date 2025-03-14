#pragma once

#include "lib/google/hooks_common.h"

#ifdef ENABLE_GOOGLE_VPC

# include "lib/eps.h"
# include "lib/l3.h"

/*
 * google_vpc_lookup_ip4_remote_endpoint performs a nested lookup for the remote endpoint and
 * overrides the incoming pointer values.
 * Each call to this function resolves to the next parent layer for the endpoint.
 * In a deployment mode with only a single nested layer, this lookup resolves to
 * the infrastructure for the remote endpoint.
 *
 * Example:
 * With one level of ipcache lookup, the pods scheduled on a VM will point to a VM node:
 *		g-org-1-shared-service-cluster  virt-launcher-vm-5e915a22-cl7bj  3/3  Running  0  20h     10.1.136.73
 *		root@worker-node3-zone1:/home/cilium# cilium bpf ipcache get 10.1.136.73
 *      10.1.136.73 maps to identity identity=89829 encryptkey=0 tunnelendpoint=10.200.0.10
 *
 * If the pod is scheduled on a BM node directly:
 *		root@worker-node3-zone1:/home/cilium# cilium bpf ipcache get 10.200.0.10
 *		10.200.0.10 maps to identity identity=6 encryptkey=0 tunnelendpoint=10.200.0.10
 */
static __always_inline int google_vpc_lookup_ip4_remote_endpoint(
	__u32 tunnel_endpoint, __u32 cluster_id,
	struct remote_endpoint_info **infra_info)
{
	struct remote_endpoint_info *info __maybe_unused;

	if (!tunnel_endpoint)
		return DROP_NO_TUNNEL_ENDPOINT;
	info = lookup_ip4_remote_endpoint(tunnel_endpoint, cluster_id);
	if (!info) {
		/* We should always have an entry in the infra-cluster.
		 * This will either map to an infra-cluster endpoint (e.g. L3 VM multi-nic), or;
		 * to an infra-cluster node (if the src in an infra-cluster pod).
		 */
		return DROP_NO_TUNNEL_ENDPOINT;
	}
	if (identity_is_node(info->sec_identity)) {
		/*
		 * If the remote endpoint is already a BM node, it means this packet is going
		 * to a infra-cluster pod. In this case we should not update the tunnel_endpoint to
		 * info->tunnel_endpoint, which will likely be 0.0.0.0.
		 */
		return CTX_ACT_OK;
	}
	*infra_info = info;
	return CTX_ACT_OK;
}

/*
 * google_vpc_lookup_ip4_endpoint performs a nested lookup for the local endpoint and
 * returns the endpoint_info if found.
 * When Google VPC is enabled, a packet coming to a VM node may not be identified correctly.
 * Here we need to do a second lookup to find the correct endpoint.
 */
static __always_inline struct endpoint_info *
google_vpc_lookup_ip4_endpoint(__u32 ip)
{
	struct endpoint_info *ep = NULL;

	/* Lookup IPv4 address in list of local endpoints and host IPs */
	ep = __lookup_ip4_endpoint(ip);
	if (!ep) {
		struct remote_endpoint_info *info = NULL;

		info = lookup_ip4_remote_endpoint(ip, 0);
		if (info && info->tunnel_endpoint)
			ep = __lookup_ip4_endpoint(info->tunnel_endpoint);
	}
	return ep;
}

static __always_inline int goog_vpc_pre_ctr_egress_fwd4(
	struct __ctx_buff *ctx, struct goog_ctr_egress_fwd4_ctx *stage_ctx)
{
	struct remote_endpoint_info *info __maybe_unused;
	void *data, *data_end;
	struct iphdr *ip4;
	__be32 daddr;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	daddr = ip4->daddr;
	if (is_defined(ENABLE_ROUTING) || stage_ctx->hairpin_flow ||
	    is_defined(ENABLE_HOST_ROUTING)) {
		/* Loopback replies are addressed to IPV4_LOOPBACK, so
		 * an endpoint lookup with ip4->daddr won't work.
		 *
		 * But as it is loopback traffic, the clientIP and backendIP
		 * are identical and we can just use the packet's saddr
		 * for the destination endpoint lookup.
		 */
		if (stage_ctx->ct_status == CT_REPLY && stage_ctx->hairpin_flow)
			daddr = ip4->saddr;
		// Double lookup if the destination endpoint is local.
		stage_ctx->local_dst_ep = google_vpc_lookup_ip4_endpoint(daddr);

		/* Update source security identity if the packet is coming from the L3 VM veth interface.
		 * An example case will be perimeter cluster node.
		 * If we do not correct the source identity here, the incoming
		 * traffic will be using SECLABEL_IPV4, which is the perimeter cluster
		 * VM node's identity, so the traffic will likely be always allowed.
		 */
# if MULTI_NIC_DEVICE_TYPE == EP_DEV_TYPE_INDEX_MULTI_NIC_VETH
		stage_ctx->src_sec_identity = WORLD_IPV4_ID;
		info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		if (info)
			stage_ctx->src_sec_identity = info->sec_identity;
# endif /* MULTI_NIC_DEVICE_TYPE == EP_DEV_TYPE_INDEX_MULTI_NIC_VETH */
	}

	// The following conditions are not supported by GDC-ag.
# if defined(ENABLE_HIGH_SCALE_IPCACHE) || \
	 defined(ENABLE_CLUSTER_AWARE_ADDRESSING)
	__throw_build_bug();
# endif

# if defined(TUNNEL_MODE)
	info = lookup_ip4_remote_endpoint(ip4->daddr, stage_ctx->cluster_id);
	if (info && info->sec_identity && info->tunnel_endpoint &&
	    !info->flag_skip_tunnel) {
		int ret;

		/*
		 * Double lookup if the destination endpoint is remote.
		 * Note we cannot do it earlier as we don't want
		 * to set dst_sec_identity to the underlying infra node's identity, which may cause
		 * the egress policy applied to wrong target. i.e., when `pod1` is trying to
		 * reach `vm1` hosted on `bm1`, we only want to check the egress policy against
		 * `pod1 -> vm1`, instead of `pod1 -> bm1`.
		 */
		ret = google_vpc_lookup_ip4_remote_endpoint(
			info->tunnel_endpoint, stage_ctx->cluster_id, &info);
		if (ret != CTX_ACT_OK)
			return ret;
		stage_ctx->remote_dst_ep = info;
	}
# endif

	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_vpc_pre_host_ingress_fwd4(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_host_ingress_fwd4_ctx_common *stage_ctx_common)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	stage_ctx_common->ep = google_vpc_lookup_ip4_endpoint(ip4->daddr);

	return HOOK_ACT_CONTINUE;
}

#else

static __always_inline int goog_vpc_pre_ctr_egress_fwd4(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_ctr_egress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_vpc_pre_host_ingress_fwd4(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_host_ingress_fwd4_ctx_common *stage_ctx_common __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif /* ENABLE_GOOGLE_VPC */
