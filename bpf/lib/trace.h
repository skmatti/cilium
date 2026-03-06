/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Packet forwarding notification via perf event ring buffer.
 *
 * API:
 * void send_trace_notify(ctx, obs_point, src, dst, dst_id, ifindex, reason, monitor)
 *
 * @ctx:	socket buffer
 * @obs_point:	observation point (TRACE_*)
 * @src:	source identity
 * @dst:	destination identity
 * @dst_id:	destination endpoint id or proxy destination port
 * @ifindex:	network interface index
 * @reason:	reason for forwarding the packet (TRACE_REASON_*),
 *		e.g. return value of ct_lookup or TRACE_REASON_ENCRYPTED
 * @monitor:	monitor aggregation value, e.g. the 'monitor' output of ct_lookup
 *
 * If TRACE_NOTIFY is not defined, the API will be compiled in as a NOP.
 */
#pragma once

#include "dbg.h"
#include "events.h"
#include "common.h"
#include "utils.h"
#include "metrics.h"
#include "ratelimit.h"

#include "lib/google/ip_options.h"
#include "tunnel.h"
#include "linux/ip.h"
#include "linux/udp.h"
#include "l4.h"
#include "lib/google/geneve_common.h"

/* Available observation points. */
enum trace_point {
	TRACE_TO_LXC,
	TRACE_TO_PROXY,
	TRACE_TO_HOST,
	TRACE_TO_STACK,
	TRACE_TO_OVERLAY,
	TRACE_FROM_LXC,
	TRACE_FROM_PROXY,
	TRACE_FROM_HOST,
	TRACE_FROM_STACK,
	TRACE_FROM_OVERLAY,
	TRACE_FROM_NETWORK,
	TRACE_TO_NETWORK,
} __packed;

/* Reasons for forwarding a packet, keep in sync with pkg/monitor/datapath_trace.go */
enum trace_reason {
	TRACE_REASON_POLICY = CT_NEW,
	TRACE_REASON_CT_ESTABLISHED = CT_ESTABLISHED,
	TRACE_REASON_CT_REPLY = CT_REPLY,
	TRACE_REASON_CT_RELATED = CT_RELATED,
	TRACE_REASON_RESERVED,
	TRACE_REASON_UNKNOWN,
	TRACE_REASON_SRV6_ENCAP,
	TRACE_REASON_SRV6_DECAP,
	TRACE_REASON_ENCRYPT_OVERLAY,
	/* Note: TRACE_REASON_ENCRYPTED is used as a mask. Beware if you add
	 * new values below it, they would match with that mask.
	 */
	TRACE_REASON_ENCRYPTED = 0x80,
} __packed;

/* Trace aggregation levels. */
enum {
	TRACE_AGGREGATE_NONE = 0,      /* Trace every packet on rx & tx */
	TRACE_AGGREGATE_RX = 1,        /* Hide trace on packet receive */
	TRACE_AGGREGATE_ACTIVE_CT = 3, /* Ratelimit active connection traces */
};

#define TRACE_EP_ID_UNKNOWN		0
#define TRACE_IFINDEX_UNKNOWN		0	/* Linux kernel doesn't use ifindex 0 */

#ifndef MONITOR_AGGREGATION
#define MONITOR_AGGREGATION TRACE_AGGREGATE_NONE
#endif

/**
 * update_trace_metrics
 * @ctx:	socket buffer
 * @obs_point:	observation point (TRACE_*)
 * @reason:	reason for forwarding the packet (TRACE_REASON_*)
 *
 * Update metrics based on a trace event
 */
#define update_trace_metrics(ctx, obs_point, reason) \
	_update_trace_metrics(ctx, obs_point, reason, __MAGIC_LINE__, __MAGIC_FILE__)
static __always_inline void
_update_trace_metrics(struct __ctx_buff *ctx, enum trace_point obs_point,
		      enum trace_reason reason, __u16 line, __u8 file)
{
	__u8 encrypted;

	switch (obs_point) {
	case TRACE_TO_LXC:
		_update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
				REASON_FORWARDED, line, file);
		break;
	case TRACE_TO_HOST:
	case TRACE_TO_STACK:
	case TRACE_TO_OVERLAY:
	case TRACE_TO_NETWORK:
		_update_metrics(ctx_full_len(ctx), METRIC_EGRESS,
				REASON_FORWARDED, line, file);
		break;
	case TRACE_FROM_HOST:
	case TRACE_FROM_STACK:
	case TRACE_FROM_OVERLAY:
	case TRACE_FROM_NETWORK:
		encrypted = reason & TRACE_REASON_ENCRYPTED;
		if (!encrypted)
			_update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
					REASON_PLAINTEXT, line, file);
		else
			_update_metrics(ctx_full_len(ctx), METRIC_INGRESS,
					REASON_DECRYPT, line, file);
		break;
	/* TRACE_FROM_LXC, i.e endpoint-to-endpoint delivery is handled
	 * separately in ipv*_local_delivery() where we can bump an egress
	 * forward. It could still be dropped but it would show up later as an
	 * ingress drop, in that scenario.
	 *
	 * TRACE_{FROM,TO}_PROXY are not handled in datapath. This is because
	 * we have separate L7 proxy "forwarded" and "dropped" (ingress/egress)
	 * counters in the proxy layer to capture these metrics.
	 */
	case TRACE_FROM_LXC:
	case TRACE_FROM_PROXY:
	case TRACE_TO_PROXY:
		break;
	}
}

struct trace_ctx {
	enum trace_reason reason;
	__u32 monitor;	/* Monitor length for number of bytes to forward in
			 * trace message. 0 means do not monitor.
			 */
};

#ifdef TRACE_NOTIFY
struct trace_notify {
	NOTIFY_CAPTURE_HDR
	__u32		src_label;
	__u32		dst_label;
	__u16		dst_id;
	__u8		reason;
	__u8		ipv6:1;
	__u8		pad:7;
	__u32		ifindex;
	union {
		struct {
			__be32		orig_ip4;
			__u32		orig_pad1;
			__u32		orig_pad2;
			__u32		orig_pad3;
		};
		union v6addr	orig_ip6;
	};
	__u64		ip_trace_id;
};

/* trace_id_from_inner_ctx depends on these. */
static __always_inline __s16 trace_id_from_inner_ctx(struct __ctx_buff *ctx __maybe_unused)
{
#ifdef ENABLE_GOOGLE_GENEVE
	void *data, *data_end;
	struct iphdr *ip4;
	struct genevehdr geneve;
	int l4_offset;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return TRACE_ID_NOT_FOUND;

	if (!geneve_is_encapped(ctx, ip4)) {
		return TRACE_ID_NOT_FOUND;
	}

	l4_offset = ETH_HLEN + (ip4->ihl << 2);
	if (ctx_load_bytes(ctx, l4_offset + sizeof(struct udphdr), &geneve, sizeof(geneve)) < 0)
		return TRACE_ID_NOT_FOUND;


	/*
	 *`trace_id_from_ip4_at` expects an offset.
	 * We can calculate the offset of the inner IP header:
	 * offset = ETH_HLEN + outer_IP_len + UDP_len + Geneve_len + Options_len
	 * outer_IP_len = ip4->ihl << 2
	 * UDP_len = sizeof(struct udphdr)
	 * Geneve_len = sizeof(struct genevehdr)
	 * Options_len = geneve.opt_len * 4
	 * so inner offset is equals to l4_offset + sizeof(struct udphdr) + sizeof(struct genevehdr) + (geneve.opt_len * 4)
	 */
	return trace_id_from_ip4_at(ctx, l4_offset + sizeof(struct udphdr) + sizeof(struct genevehdr) + (geneve.opt_len * 4));
#endif
	return TRACE_ID_NOT_FOUND;
}

static __always_inline bool
emit_trace_notify(enum trace_point obs_point, __u32 monitor)
{
	if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_RX) {
		switch (obs_point) {
		case TRACE_FROM_LXC:
		case TRACE_FROM_PROXY:
		case TRACE_FROM_HOST:
		case TRACE_FROM_STACK:
		case TRACE_FROM_OVERLAY:
		case TRACE_FROM_NETWORK:
			return false;
		default:
			break;
		}
	}

	/*
	 * Ignore sample when aggregation is enabled and 'monitor' is set to 0.
	 * Rate limiting (trace message aggregation) relies on connection tracking,
	 * so if there is no CT information available at the observation point,
	 * then 'monitor' will be set to 0 to avoid emitting trace notifications
	 * when aggregation is enabled (the default).
	 */
	if (MONITOR_AGGREGATION >= TRACE_AGGREGATE_ACTIVE_CT && !monitor)
		return false;

	return true;
}

#define send_trace_notify(ctx, obs_point, src, dst, dst_id, ifindex, reason, monitor) \
		_send_trace_notify(ctx, obs_point, src, dst, dst_id, ifindex, reason, monitor, \
		__MAGIC_LINE__, __MAGIC_FILE__)
static __always_inline void
_send_trace_notify(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src, __u32 dst, __u16 dst_id, __u32 ifindex,
		   enum trace_reason reason, __u32 monitor, __u16 line, __u8 file)
{
	__s16 trace_id = 0;
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, monitor ? : TRACE_PAYLOAD_LEN,
			      ctx_len);
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_EVENTS_MAP,
	};
	struct ratelimit_settings settings = {
		.topup_interval_ns = NSEC_PER_SEC,
	};
	struct trace_notify msg __align_stack_8;

	/*
	 * The trace_id is used to skip aggregation, rate limiting, and set identity
	 * fields so that this traffic can be found in Hubble.
	 * For GENEVE encapsulated packets presence of trace_id is verified  by `trace_id_from_inner_ctx`
	*/
	trace_id = trace_id_from_ctx(ctx);
	if (trace_id <= 0)
		trace_id = trace_id_from_inner_ctx(ctx);

	_update_trace_metrics(ctx, obs_point, reason, line, file);

	if (trace_id <= 0 && !emit_trace_notify(obs_point, monitor))
		return;

	if (EVENTS_MAP_RATE_LIMIT > 0) {
		settings.bucket_size = EVENTS_MAP_BURST_LIMIT;
		settings.tokens_per_topup = EVENTS_MAP_RATE_LIMIT;
		if (!ratelimit_check_and_take(&rkey, &settings))
			return;
	}

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_TRACE, obs_point),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.src_label	= src,
		.dst_label	= dst,
		.dst_id		= dst_id,
		.reason		= reason,
		.ifindex	= ifindex,
		.ipv6		= 0,
		.ip_trace_id	= trace_id,
	};
	memset(&msg.orig_ip6, 0, sizeof(union v6addr));

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static __always_inline void
send_trace_notify4(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src, __u32 dst, __be32 orig_addr, __u16 dst_id,
		   __u32 ifindex, enum trace_reason reason, __u32 monitor)
{
	__s16 trace_id = 0;
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, monitor ? : TRACE_PAYLOAD_LEN,
			      ctx_len);
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_EVENTS_MAP,
	};
	struct ratelimit_settings settings = {
		.topup_interval_ns = NSEC_PER_SEC,
	};
	struct trace_notify msg __align_stack_8;

	// The trace_id is used to skip aggregation, rate limiting, and set identity
	// fields so that this traffic can be found in Hubble.
	trace_id = trace_id_from_ctx(ctx);
	if (trace_id <= 0)
		trace_id = trace_id_from_inner_ctx(ctx);

	update_trace_metrics(ctx, obs_point, reason);

	if (trace_id <= 0 && !emit_trace_notify(obs_point, monitor))
		return;

	if (EVENTS_MAP_RATE_LIMIT > 0) {
		settings.bucket_size = EVENTS_MAP_BURST_LIMIT;
		settings.tokens_per_topup = EVENTS_MAP_RATE_LIMIT;
		if (!ratelimit_check_and_take(&rkey, &settings))
			return;
	}

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_TRACE, obs_point),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.src_label	= src,
		.dst_label	= dst,
		.dst_id		= dst_id,
		.reason		= reason,
		.ifindex	= ifindex,
		.ipv6		= 0,
		.orig_ip4	= orig_addr,
		.ip_trace_id	= trace_id,
	};

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}

static __always_inline void
send_trace_notify6(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src, __u32 dst, const union v6addr *orig_addr,
		   __u16 dst_id, __u32 ifindex, enum trace_reason reason,
		   __u32 monitor)
{
	__u64 ctx_len = ctx_full_len(ctx);
	__u64 cap_len = min_t(__u64, monitor ? : TRACE_PAYLOAD_LEN,
			      ctx_len);
	struct ratelimit_key rkey = {
		.usage = RATELIMIT_USAGE_EVENTS_MAP,
	};
	struct ratelimit_settings settings = {
		.topup_interval_ns = NSEC_PER_SEC,
	};
	struct trace_notify msg __align_stack_8;

	update_trace_metrics(ctx, obs_point, reason);

	if (!emit_trace_notify(obs_point, monitor))
		return;

	if (EVENTS_MAP_RATE_LIMIT > 0) {
		settings.bucket_size = EVENTS_MAP_BURST_LIMIT;
		settings.tokens_per_topup = EVENTS_MAP_RATE_LIMIT;
		if (!ratelimit_check_and_take(&rkey, &settings))
			return;
	}

	msg = (typeof(msg)) {
		__notify_common_hdr(CILIUM_NOTIFY_TRACE, obs_point),
		__notify_pktcap_hdr(ctx_len, (__u16)cap_len),
		.src_label	= src,
		.dst_label	= dst,
		.dst_id		= dst_id,
		.reason		= reason,
		.ifindex	= ifindex,
		.ipv6		= 1,
	};

	ipv6_addr_copy(&msg.orig_ip6, orig_addr);

	ctx_event_output(ctx, &EVENTS_MAP,
			 (cap_len << 32) | BPF_F_CURRENT_CPU,
			 &msg, sizeof(msg));
}
#else
static __always_inline void
send_trace_notify(struct __ctx_buff *ctx, enum trace_point obs_point,
		  __u32 src __maybe_unused, __u32 dst __maybe_unused,
		  __u16 dst_id __maybe_unused, __u32 ifindex __maybe_unused,
		  enum trace_reason reason, __u32 monitor __maybe_unused)
{
	update_trace_metrics(ctx, obs_point, reason);
}

static __always_inline void
send_trace_notify4(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src __maybe_unused, __u32 dst __maybe_unused,
		   __be32 orig_addr __maybe_unused, __u16 dst_id __maybe_unused,
		   __u32 ifindex __maybe_unused, enum trace_reason reason,
		   __u32 monitor __maybe_unused)
{
	update_trace_metrics(ctx, obs_point, reason);
}

static __always_inline void
send_trace_notify6(struct __ctx_buff *ctx, enum trace_point obs_point,
		   __u32 src __maybe_unused, __u32 dst __maybe_unused,
		   union v6addr *orig_addr __maybe_unused,
		   __u16 dst_id __maybe_unused, __u32 ifindex __maybe_unused,
		   enum trace_reason reason, __u32 monitor __maybe_unused)
{
	update_trace_metrics(ctx, obs_point, reason);
}
#endif /* TRACE_NOTIFY */
