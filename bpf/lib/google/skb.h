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
