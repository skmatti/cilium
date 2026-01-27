#pragma once

#include <bpf/ctx/skb.h>

#ifndef ctx_redirect
/* Only override ctx_redirect when it's not already defined as macro.
 * In some of the bpf tests, ctx_redirect is already overriden with
 * mock redirect function, we don't want to break these tests.
 *
 * We cannot judge by BPF_TEST, as in some bpf tests where the ctx_redirect
 * is not mocked, we want the below redirection actually happen.
 */
# define ctx_redirect google_ctx_redirect

static __always_inline int google_geneve_ctx_redirect(
	struct __ctx_buff *ctx __maybe_unused, int ifindex, const __u32 flags);

static __always_inline int
google_ctx_redirect(struct __ctx_buff *ctx, int ifindex, __u32 flags)
{
	return google_geneve_ctx_redirect(ctx, ifindex, flags);
}

#endif

// In TC we don't modify these functions.
#ifndef google_ctx_load_bytes
#define google_ctx_load_bytes ctx_load_bytes
#endif
#ifndef google_ctx_adjust_hroom
static __always_inline int google_ctx_adjust_hroom(
	struct __ctx_buff *ctx, const __s32 len_diff, const __u32 mode,
	const __u64 flags)
{
	if (len_diff < 0 && mode == BPF_ADJ_ROOM_MAC) {
		/* Kernel doesn't support shrinking with BPF_ADJ_ROOM_MAC (-ENOTSUPP).
		 * Shrinking with BPF_ADJ_ROOM_NET achieves the exact same effect:
		 * it removes bytes at the start of the network header (after MAC). */
		return ctx_adjust_hroom(ctx, len_diff, BPF_ADJ_ROOM_NET, flags);
	}
	return ctx_adjust_hroom(ctx, len_diff, mode, flags);
}
#endif
