#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "lib/trace.h"

struct from_host_netdev_context {
	__u32 trace_monitor;
	__u32 trace_reason;
	__u32 magic;
	bool from_proxy;
	bool to_endpoint;
	__u8 pad[2];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct from_host_netdev_context);
	__uint(max_entries, 1);
} goog_from_host_netdev_context __section_maps_btf;

static __always_inline
int goog_ipv4_from_host_netdev_fwd_store_state(struct trace_ctx *trace,
					       __u32 magic, bool from_proxy,
					       bool to_endpoint)
{
	struct from_host_netdev_context ctx = {
		.trace_reason = (__u32)trace->reason,
		.trace_monitor = trace->monitor,
		.magic = magic,
		.from_proxy = from_proxy,
		.to_endpoint = to_endpoint,
	};
	__u32 zero = 0;

	return map_update_elem(&goog_from_host_netdev_context, &zero, &ctx, 0);
}

static __always_inline
int goog_ipv4_from_lxc_fwd_restore_state(struct trace_ctx *trace,
					 __u32 *magic, bool *from_proxy,
					 bool *to_endpoint)
{
	struct from_host_netdev_context *ctx;
	__u32 zero = 0;

	ctx = map_lookup_elem(&goog_from_host_netdev_context, &zero);
	if (!ctx)
		return DROP_INVALID;

	trace->reason = (enum trace_reason)ctx->trace_reason;
	trace->monitor = ctx->trace_monitor;
	*magic = ctx->magic;
	*from_proxy = ctx->from_proxy;
	*to_endpoint = ctx->to_endpoint;

	return 0;
}

