#pragma once

#include <bpf/ctx/xdp.h>

#define GOOGLE_CTX_MAX_LOAD_BYTES 512

/* google_ctx_load_bytes is a wrapper around ctx_load_bytes that uses direct
 * packet access for XDP to avoid verifier errors.
 *
 * When using ctx_load_bytes (which contains inline ASM for XDP) inside a loop
 * (like trace_id_from_ip4), LLVM generates complex code with high register
 * pressure. This can cause the verifier to reject the program with "invalid
 * size of register spill" errors, as 64-bit pointers (like pkt_end) get
 * spilled as 32-bit values.
 *
 * By using direct packet access for XDP, we simplify the generated code and
 * avoid this register pressure.
 */
static __always_inline int google_ctx_load_bytes(
	struct __ctx_buff *ctx, __u32 offset, void *to, const __u32 len)
{
	void *data_end = ctx_data_end(ctx);
	void *data = ctx_data(ctx);
	__u8 *cursor;
	__u8 *dst;
	__u32 i;

	if ((void *)data + offset + len > data_end)
		return -1;

	/* Safety limit to avoid huge unrolling and verifier complexity */
	if (len > GOOGLE_CTX_MAX_LOAD_BYTES)
		return -1;

	if (__builtin_constant_p(len)) {
		__bpf_memcpy_builtin(to, data + offset, len);
		return 0;
	}

	cursor = (__u8 *)data + offset;
	dst = (__u8 *)to;

	/* Fallback optimized loop for variable lengths */
	for (i = 0; i < GOOGLE_CTX_MAX_LOAD_BYTES; i++) {
		if (i >= len)
			break;
		if ((void *)(cursor + 1) > data_end)
			return -1;
		*dst++ = *cursor++;
	}

	return 0;
}

static __always_inline int google_ctx_adjust_hroom(
	struct __ctx_buff *ctx, const __s32 len_diff, const __u32 mode,
	const __u64 flags __maybe_unused)
{
	if (mode != BPF_ADJ_ROOM_MAC && mode != BPF_ADJ_ROOM_NET)
		return CTX_ACT_DROP;

	/* The cilium ctx_adjust_hroom for XDP (in bpf/ctx/xdp.h) has a limited whitelist.
	 * We override it here to support dynamic adjustment required for Geneve DSR.
	 */
	if (len_diff > 0) {
		void *data_end;
		void *data;
		int move_len = 14; /* Default: move Eth only */

		if (len_diff > 256)
			return CTX_ACT_DROP;

		/* Determine how much to move based on len_diff (tailored for DSR) */
		switch (len_diff) {
		case 4:  /* struct trace_opt_v4 */
			move_len = 34;
			break;
		case 8:  /* IPv4 DSR: Eth(14) + IPv4(20) = 34 */
			move_len = 34;
			break;
		case 20: /* IPv4 header */
			move_len = 14;
			break;
		case 12: /* Geneve DSR opt4: Eth(14) + IPv4(20) + UDP(8) + Geneve(8) = 50 */
			move_len = 50;
			break;
		case 24: /* IPv6 DSR: Eth(14) + IPv6(40) = 54 */
		case 40: /* IPv6 header */
			move_len = 54;
			break;
		}

		if (xdp_adjust_head(ctx, -len_diff))
			return CTX_ACT_DROP;

		data_end = ctx_data_end(ctx);
		data = ctx_data(ctx);

		/* Move headers [data+len_diff, data+len_diff+move_len) to [data, data+move_len) */
		if (data + move_len + len_diff <= data_end) {
			switch (move_len) {
			case 14:
				__bpf_memmove_fwd(data, data + len_diff, 14);
				break;
			case 34:
				__bpf_memmove_fwd(data, data + len_diff, 34);
				break;
			case 50:
				__bpf_memmove_fwd(data, data + len_diff, 50);
				break;
			case 54:
				__bpf_memmove_fwd(data, data + len_diff, 54);
				break;
			default:
				/* Should not happen given the cases above, but safety check */
				if (__builtin_constant_p(move_len))
					__bpf_memmove_fwd(data, data + len_diff, move_len);
				else
					return CTX_ACT_DROP;
			}
		} else {
			return CTX_ACT_DROP;
		}

		return 0;
	} else if (len_diff < 0) {
		void *data_end = ctx_data_end(ctx);
		void *data = ctx_data(ctx);
		struct ethhdr eth;

		if (data + 14 > data_end)
			return CTX_ACT_DROP;

		eth = *(struct ethhdr *)data;

		if (xdp_adjust_head(ctx, -len_diff))
			return CTX_ACT_DROP;

		data = ctx_data(ctx);
		data_end = ctx_data_end(ctx);

		if (data + 14 > data_end)
			return CTX_ACT_DROP;

		*(struct ethhdr *)data = eth;

		return 0;
	}
	// len_diff == 0, nothing to do
	return 0;
}
