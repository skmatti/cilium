#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

struct from_lxc_context {
	__u32 dst_sec_identity;
	__u32 tunnel_endpoint;
	__u8 encrypt_key;
	bool skip_tunnel;
	__u8 pad[6];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct from_lxc_context);
	__uint(max_entries, 1);
} goog_from_lxc_context __section_maps_btf;

static __always_inline
int goog_ipv4_from_lxc_fwd_store_state(__u8 encrypt_key, __u32 tunnel_endpoint,
				       bool skip_tunnel, __u32 dst_sec_identity)
{
	struct from_lxc_context ctx = {
		.dst_sec_identity = dst_sec_identity,
		.tunnel_endpoint = tunnel_endpoint,
		.encrypt_key = encrypt_key,
		.skip_tunnel = skip_tunnel,
	};
	__u32 zero = 0;

	return map_update_elem(&goog_from_lxc_context, &zero, &ctx, 0);
}

static __always_inline
int goog_ipv4_from_lxc_fwd_restore_state(__u8 *encrypt_key,
					 __u32 *tunnel_endpoint,
					 bool *skip_tunnel,
					 __u32 *dst_sec_identity)
{
	struct from_lxc_context *ctx;
	__u32 zero = 0;

	ctx = map_lookup_elem(&goog_from_lxc_context, &zero);
	if (!ctx)
		return DROP_INVALID;

	*dst_sec_identity = ctx->dst_sec_identity;
	*tunnel_endpoint = ctx->tunnel_endpoint;
	*encrypt_key = ctx->encrypt_key;
	*skip_tunnel = ctx->skip_tunnel;

	return 0;
}

