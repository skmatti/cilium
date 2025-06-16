#pragma once

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "hooks_common.h"

#include "lib/google_pip.h"
#include "lib/google/plugin.h"

#ifdef ENABLE_GOOGLE_PERSISTENT_IP

#ifdef IS_BPF_HOST

static __always_inline
int goog_maybe_try_pip_ingress_redirect4(struct __ctx_buff *ctx,
					 struct goog_host_ingress_fwd4_ctx_common *stage_ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	ret = google_try_pip_ingress_redirect4(ctx, stage_ctx->secctx, ip4);
	if (ret != CTX_ACT_OK)
		return ret;

	return HOOK_ACT_CONTINUE;
}

#endif /* IS_BPF_HOST */

#ifdef IS_BPF_LXC

static __always_inline
int goog_maybe_try_pip_egress_redirect4(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	int ret;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	ret = google_try_pip_egress_redirect4(ctx, ip4);
	if (ret != CTX_ACT_OK)
		return ret;

	return HOOK_ACT_CONTINUE;
}

#endif /* IS_BPF_LXC */

#else

#ifdef IS_BPF_HOST

static __always_inline
int goog_maybe_try_pip_ingress_redirect4(struct __ctx_buff *ctx __maybe_unused,
					 struct goog_host_ingress_fwd4_ctx_common *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif /* IS_BPF_HOST */

#ifdef IS_BPF_LXC

static __always_inline
int goog_maybe_try_pip_egress_redirect4(struct __ctx_buff *ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif /* IS_BPF_LXC */

#endif /* ENABLE_GOOGLE_PERSISTENT_IP */
