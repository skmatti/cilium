#pragma once

#if defined(ENABLE_EGRESS_GATEWAY_REDIRECT) || defined(GOOGLE_PERIMETER_FEATURES)

#include "lib/common.h"
#include "lib/google/geneve.h"
#include "lib/conntrack.h"
#include "lib/conntrack_map.h"
#include "lib/eps.h"
#include "lib/google/vpc.h"
#include "lib/encap.h"
#include "lib/google/hooks_common.h"
#include "lib/egress_gateway.h"
#include "lib/google_maps.h"
#include "lib/google_perimeter_common.h"

static __always_inline __u16 generate_new_ep(void)
{
	return (__u16)get_prandom_u32() + 1;
}

static __always_inline
void google_perimeter__set_geneve_hdr_opt(__be32 addr, __u8 direction_flag,
					  struct geneve_perimeter_opt4 *gopt)
{
	memset(gopt, 0, sizeof(*gopt));

	gopt->hdr.opt_class = bpf_htons(GOOGLE_GENEVE_OPT_CLASS);
	gopt->hdr.type = direction_flag;
	gopt->hdr.length = PERIMETER_IPV4_GENEVE_OPT_LEN;
	gopt->addr = addr;
}

/* Build geneve header for a packet ingressing the cluster. */
static __always_inline
void google_perimeter__set_geneve_perimeter_ingress_opt4(__be32 addr,
							 struct geneve_perimeter_opt4
							 *gopt)
{
	google_perimeter__set_geneve_hdr_opt(addr, PERIMETER_GENEVE_INGRESS_OPT_TYPE,
					     gopt);
}

/* Build geneve header for a packet egressing the cluster. */
static __always_inline
void google_perimeter__set_geneve_perimeter_egress_opt4(__be32 addr,
							struct geneve_perimeter_opt4
							*gopt)
{
	google_perimeter__set_geneve_hdr_opt(addr, PERIMETER_GENEVE_EGRESS_OPT_TYPE,
					     gopt);
}

static __always_inline
bool google_perimeter__is_elb_traffic(struct ct_state conntrack_state)
{
	return (conntrack_state.dsr_internal && conntrack_state.rev_nat_index);
}

static __always_inline
int google_perimeter__init_perimeter_ct_entry(struct __ctx_buff *ctx,
					      struct ipv4_ct_tuple *tuple,
					      __u16 *ep_id)
{
	struct ct_state ct_state_new = {};
	int ret;

	ct_state_new.src_sec_id = WORLD_ID;
	ct_state_new.node_port = 0;
# ifndef HAVE_FIB_IFINDEX
	ct_state_new.ifindex = (__u16)NATIVE_DEV_IFINDEX;
# endif
	ct_state_new.rev_nat_index = *ep_id;
	ct_state_new.dsr_internal = 1;

	/* TODO: (lconnery - b/437150889) Migrate GDC LB implementation to use
	 * Perimeter Conntrack map
	 */
	ret = ct_create4(get_ct_map4(tuple), NULL, tuple, ctx, CT_INGRESS,
			 &ct_state_new, NULL /* error */);

	return ret;
}

static __always_inline
int __encap_and_redirect_with_nodeid_opt(struct __ctx_buff *ctx,
					 __u32 src_ip,
					 __be32 tunnel_endpoint,
					 __u32 seclabel,
					 __u32 dstid,
					 __u32 vni,
					 void *opt,
					 __u32 opt_len,
					 const struct trace_ctx *trace)
{
	int ifindex;
	int ret = 0;

	ret = __encap_with_nodeid_opt(ctx, src_ip, 0, tunnel_endpoint, seclabel,
				      dstid, vni, opt, opt_len, trace->reason,
				      trace->monitor, &ifindex);

	if (ret != CTX_ACT_REDIRECT)
		return ret;

	return google_geneve_ctx_redirect(ctx, ifindex, 0);
}

/*
 * This function creates the required entries in the perimeter endpoint map so
 * that the correct perimeter node can be found on the reverse flow.
 *
 * Called from bpf_lxc's from_container when the backend is local to the
 * perimeter node pod.
 *
 * Called from bpf_host's from_netdev (on the remote node) when the backend pod
 * is not running on the same node as the perimeter node pod.
 *
 * https://screenshot.googleplex.com/7RuPhggajjsxLnC
 *
 */

#ifdef ENABLE_EGRESS_GATEWAY_REDIRECT

static __always_inline
int google_perimeter__handle_perimeter_lb_traffic(struct __ctx_buff *ctx,
						  __u32 perimeter_gw_ip)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct ipv4_ct_tuple tuple = {};
	int ret, l4_off;
	struct ct_state ct_state = {};
	__u32 monitor = 0;
	__u16 *ep_id = NULL;
	__u16 new_ep = 0;
	struct ipv4_redirect_ep lookup_ip = {};
	struct remote_endpoint_info *info = NULL;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	info = lookup_ip4_remote_endpoint(ip4->saddr, 0);

	if (info && identity_is_cluster(info->sec_identity)) {
		/* Source is not external, return to bpf_lxc/bpf_host to continue normal
		 * behaviour.
		 */
		return HOOK_ACT_CONTINUE;
	}

	lb4_extract_tuple(ctx, ip4, ETH_HLEN, &l4_off, &tuple);

	lookup_ip.ip4 = perimeter_gw_ip;
	ep_id = map_lookup_elem(&GOOGLE_REDIRECT_EP_ID_V4_MAP, &lookup_ip);

	if (!ep_id) {
		new_ep = generate_new_ep();

		/*
		 * Update GOOGLE_REDIRECT_EP_IP_V4_MAP first to avoid ID collision.
		 * Use the new endpoint ID as the key, mapping it to the lookup IP.
		 * the BPF_NOEXIST flag ensures that we do not overwrite an existing entry.
		 * This update will fail if the new endpoint ID is already in use.
		 */
		ret = map_update_elem(&GOOGLE_REDIRECT_EP_IP_V4_MAP, &new_ep,
				      &lookup_ip, BPF_NOEXIST);

		if (ret < 0)
			return DROP_UNROUTABLE;

		ret = map_update_elem(&GOOGLE_REDIRECT_EP_ID_V4_MAP, &lookup_ip,
				      &new_ep, BPF_NOEXIST);

		if (ret < 0)
			return DROP_UNROUTABLE;

		ep_id = map_lookup_elem(&GOOGLE_REDIRECT_EP_ID_V4_MAP, &lookup_ip);

		if (!ep_id)
			return DROP_UNROUTABLE;
	}

	ret = ct_lookup4(get_ct_map4(&tuple), &tuple, ctx, ip4, l4_off,
			 CT_INGRESS, &ct_state, &monitor);

	switch (ret) {
	case CT_NEW:
redo:
		ret = google_perimeter__init_perimeter_ct_entry(ctx, &tuple, ep_id);

		if (IS_ERR(ret))
			return ret;

		break;

	case CT_REOPENED:
	case CT_ESTABLISHED:
		/*
		 * Recreate CT entries, as the existing one is stale and
		 * belongs to a flow which target a different svc.
		 */
		if (unlikely(ct_state.rev_nat_index != *ep_id ||
			     ct_state.dsr_internal != 1))
			goto redo;

		break;
	case CT_RELATED:
	case CT_REPLY:
		break;
	default:
		return DROP_UNKNOWN_CT;
	}

	return HOOK_ACT_CONTINUE;
}

#else

static __always_inline
int google_perimeter__handle_perimeter_lb_traffic(struct __ctx_buff *ctx __maybe_unused,
						  __u32 perimeter_gw_ip __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif /* ENABLE_EGRESS_GATEWAY_REDIRECT */

static __always_inline
int google_perimeter__redirect_to_perimeter_gateway(struct __ctx_buff *ctx,
						    struct iphdr *ip4,
						    const struct trace_ctx *trace,
						    __u32 perimeter_gw_ip)
{
	struct geneve_perimeter_opt4 gopt;
	struct endpoint_info *lep;
	struct remote_endpoint_info *rep;

	__u32 dst_id = 0; /* used for send_trace_notify */

	lep = __lookup_ip4_endpoint(perimeter_gw_ip);

	/* Check if Perimeter Gateway is a local endpoint */
	if (lep) {
		/* Send packet to perimeter gateway endpoint using local delivery */
		return ipv4_local_delivery(ctx, ETH_HLEN, SECLABEL, MARK_MAGIC_IDENTITY,
					   ip4, lep, METRIC_EGRESS, false, false, 0);
	}

	/* Check if Perimeter Gateway is a remote endpoint */
	rep = lookup_ip4_remote_endpoint(perimeter_gw_ip, 0);

	if (rep && rep->tunnel_endpoint) {
		/* Set perimeter gateway IP as a tunnel option
		 * and send it to the node hosting the perimeter gateway.
		 */
		google_perimeter__set_geneve_perimeter_egress_opt4(perimeter_gw_ip, &gopt);

		return __encap_and_redirect_with_nodeid_opt(ctx, 0,
							    rep->tunnel_endpoint,
							    SECLABEL_IPV4,
							    dst_id, 0,
							    &gopt,
							    sizeof(gopt), trace);
	}

	/* If perimeter gateway is not found, we drop the packet.*/
	return DROP_NO_EGRESS_GATEWAY;
}

/*
 * The packet is on the reverse path and a part of ELB traffic exiting the
 * backend pod at the LXC program's from_container entry point.
 *
 * Look up perimeter node IP from Perimeter Redirect maps and route to
 * perimeter node.
 *
 * Local Backend:
 * https://screenshot.googleplex.com/AqBFKKMxXokxsXX
 *
 * Remote Backend:
 * https://screenshot.googleplex.com/4uwBALNnwhiueWc
 */

#ifdef ENABLE_EGRESS_GATEWAY_REDIRECT

static __always_inline
int google_perimeter__from_container_elb_reverse_path(struct __ctx_buff *ctx,
						      struct ct_state *ct_state,
						      struct iphdr *ip4,
						      const struct trace_ctx *trace)
{
	struct ipv4_redirect_ep *perip;

	perip = map_lookup_elem(&GOOGLE_REDIRECT_EP_IP_V4_MAP,
				&ct_state->rev_nat_index);

	if (!perip)
		return DROP_HOST_UNREACHABLE;

	return google_perimeter__redirect_to_perimeter_gateway(ctx, ip4,
							       trace, perip->ip4);
}

#else

static __always_inline
int google_perimeter__from_container_elb_reverse_path(struct __ctx_buff *ctx __maybe_unused,
						      struct ct_state *ct_state __maybe_unused,
						      struct iphdr *ip4 __maybe_unused,
						      const struct trace_ctx *trace __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}


#endif /* ENABLE_EGRESS_GATEWAY_REDIRECT */

/*
 * For ELB traffic, the packet is leaving the perimeter node through the pod's
 * LXC from_container entry point.
 *
 * In the case of a local backend, this perimeter nodes IP is saved to the
 * Perimeter Redirect tables and the packet is sent to local delivery.
 *
 * For remote backends, the perimeter node IP is stored in the geneve header
 * options.
 *
 * Local Backend:
 * https://screenshot.googleplex.com/BKkM65q4FuBQAey
 *
 * Remote Backend:
 * https://screenshot.googleplex.com/747ZVUswGAsR94x
 */

#ifdef PERIMETER_ENDPOINT

static __always_inline
int google_perimeter__from_container_elb_forward_path(struct __ctx_buff *ctx,
						      struct goog_ctr_egress_fwd4_ctx *stage_ctx,
						      struct iphdr *ip4,
						      const struct trace_ctx *trace)
{
	struct geneve_perimeter_opt4 gopt;
	struct remote_endpoint_info *rep;
	struct endpoint_info *lep = NULL;
	int ret;

	__u32 dst_id = 0; /* used for send_trace_notify */

	/* Check if this is ELB traffic */
	if (stage_ctx->ct_status == CT_REPLY || stage_ctx->ct_status == CT_RELATED)
		return HOOK_ACT_CONTINUE;

	/* TODO: lconnery (b/450614670) We need to check SRC IP identity_is_cluster */

	/* Backend pod is running on the same node as the perimeter node */
	lep = __lookup_ip4_endpoint(ip4->daddr);

	if (lep) {
		ret = google_perimeter__handle_perimeter_lb_traffic(ctx, LXC_IPV4);

		if (IS_ERR(ret))
			return ret;

		return ipv4_local_delivery(ctx, ETH_HLEN, SECLABEL,
					   MARK_MAGIC_IDENTITY,
					   ip4, lep, METRIC_EGRESS,
					   false, false, 0);
	}

	/* Backend pod is on a remote node relative to the perimeter node */
	rep = lookup_ip4_remote_endpoint(ip4->daddr, 0);

	if (rep && identity_is_cluster(rep->sec_identity)) {
		ret = google_vpc_lookup_ip4_remote_endpoint(rep->tunnel_endpoint, stage_ctx->cluster_id, &rep);

		if (IS_ERR(ret))
			return ret;

		if (!rep->tunnel_endpoint)
			return HOOK_ACT_CONTINUE;

		/* Setting geneve perimeter ip to the current LXC IP */
		google_perimeter__set_geneve_perimeter_ingress_opt4(LXC_IPV4, &gopt);

		return __encap_and_redirect_with_nodeid_opt(ctx, 0, rep->tunnel_endpoint, SECLABEL_IPV4,
							    dst_id, 0, &gopt, sizeof(gopt), trace);
	}

	return HOOK_ACT_CONTINUE;
}

#else

static __always_inline
int google_perimeter__from_container_elb_forward_path(struct __ctx_buff *ctx __maybe_unused,
						      struct goog_ctr_egress_fwd4_ctx *stage_ctx __maybe_unused,
						      struct iphdr *ip4 __maybe_unused,
						      const struct trace_ctx *trace __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif /* PERIMETER_ENDPOINT */

/*
 * TOP LEVE ELB ENTRY POINT: bfp_lxc/from_container
 *
 * For ELB traffic, the packet is either exiting the perimeter node on the
 * forward path or exiting the backend pod on the reverse path.
 *
 * https://screenshot.googleplex.com/3DXceqXnBrSMJ3h
 */

static __always_inline
int google_perimeter__handle_perimeter_endpoint_lxc(struct __ctx_buff *ctx,
						    struct goog_ctr_egress_fwd4_ctx *stage_ctx)
{
	struct trace_ctx trace = {};
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	if (stage_ctx->ct_status == CT_REPLY || stage_ctx->ct_status == CT_RELATED) {
		struct ct_state ct_state = {};

		ct_state.rev_nat_index = stage_ctx->rev_nat_index;
		ct_state.dsr_internal = stage_ctx->dsr_internal;

		if (!google_perimeter__is_elb_traffic(ct_state))
			return HOOK_ACT_CONTINUE;

		return google_perimeter__from_container_elb_reverse_path(ctx, &ct_state,
									 ip4, &trace);
	}

	return google_perimeter__from_container_elb_forward_path(ctx, stage_ctx, ip4, &trace);
}

/*
 * TOP LEVEL ELB ENTRY POINT: bfp_host/from_netdev
 *
 * For ELB traffic, the packet is either entering the bare metal node hosting
 * the backend pod on the forward path or arriving back at the bare metal node
 * hosting the perimeter node.
 *
 * The geneve opt types
 *
 * - PERIMETER_GENEVE_INGRESS_OPT_TYPE
 * - PERIMETER_GENEVE_EGRESS_OPT_TYPE
 *
 * determines the flow of direction relative to the deployment.
 *
 * https://screenshot.googleplex.com/8uiaobNLHTfAwfM
 */
static __always_inline
int google_perimeter__handle_perimeter_endpoint_host(struct __ctx_buff *ctx,
						     struct goog_host_ingress_fwd4_ctx_common
						     *stage_ctx_common)
{
	struct geneve_perimeter_opt4 *perimeter_metadata;

	perimeter_metadata = (struct geneve_perimeter_opt4 *)
		geneve_get_option_from_metadata(geneve_get_metadata(GENEVE_DIR_INGRESS),
						GOOGLE_GENEVE_OPT_CLASS,
						PERIMETER_GENEVE_INGRESS_OPT_TYPE);

	if (perimeter_metadata) {
		/* Handle perimeter option on ingress */
		if (perimeter_metadata->addr == 0)
			return DROP_UNROUTABLE;

		return google_perimeter__handle_perimeter_lb_traffic(ctx,
								     perimeter_metadata->addr);
	}

	perimeter_metadata = (struct geneve_perimeter_opt4 *)
		geneve_get_option_from_metadata(geneve_get_metadata(GENEVE_DIR_INGRESS),
						GOOGLE_GENEVE_OPT_CLASS,
						PERIMETER_GENEVE_EGRESS_OPT_TYPE);

	if (perimeter_metadata) {
		struct endpoint_info *ep;

		/* Handle perimeter option on egress */
		if (perimeter_metadata->addr == 0)
			return DROP_UNROUTABLE;

		ep = __lookup_ip4_endpoint(perimeter_metadata->addr);
		if (!ep) {
			/* Packet entered the node with a Perimeter Gateway Egress Option, its either:
			 * 1. EgressNAT Forward Path
			 * 2. ELB Reverse Path
			 * In either case, packet should go directly to the infra node hosting the perimeter gateway.
			 * Since there is no endpoint matching perimeter IP here, this packet is invalid and should be dropped.
			 */
			return DROP_UNROUTABLE;
		}

		stage_ctx_common->ep = ep;
	}

	return HOOK_ACT_CONTINUE;
}

#endif
