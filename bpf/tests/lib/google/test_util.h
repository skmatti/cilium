
struct geneve_opt_test_ctx {
	__u8 hdr_type;
	__u8 hdr_length;
	__be32 ip_opt;
	const volatile __u8 *src_mac;
	const volatile __u8 *dst_mac;
	__be32 outer_src_ip;
	__be32 outer_dst_ip;
};

const __u32 MIN_GENEVE_SRC_PORT = (0 | 0x8000);

static __always_inline int geneve_ip_opt_check(const struct __ctx_buff *ctx,
					       struct geneve_opt_test_ctx test_ctx)
{
	test_init();
	struct geneve_perimeter_opt4 *gopt;
	struct ethhdr *l2, *inner_l2;
	struct iphdr *l3, *inner_l3;
	struct tcphdr *tcp_inner;
	struct genevehdr *geneve;
	void *data, *data_end;
	__u32 *status_code;
	struct udphdr *udp;

	data = (void *)(long)ctx_data(ctx);
	data_end = (void *)(long)ctx->data_end;
	if (data + sizeof(__u32) > data_end)
		test_fatal("status code out of bounds");
	status_code = data;
	assert(*status_code == TC_ACT_REDIRECT);
	l2 = data + sizeof(__u32);
	if ((void *)l2 + sizeof(*l2) > data_end)
		test_fatal("outer l2 out of bounds");
	/* Outer L2 Checks */
	if (memcmp(l2->h_source, (const void *)test_ctx.src_mac, ETH_ALEN) != 0)
		test_fatal("incorrect src MAC");
	if (memcmp(l2->h_dest, (const void *)test_ctx.dst_mac, ETH_ALEN) != 0)
		test_fatal("incorrect dst MAC");
	l3 = (void *)l2 + sizeof(*l2);
	if ((void *)l3 + sizeof(*l3) > data_end)
		test_fatal("outer l3 out of bounds");
	/* Outer L3 Checks */
	if (l3->saddr != test_ctx.outer_src_ip)
		test_fatal("incorrect outer src IP");
	if (l3->daddr != test_ctx.outer_dst_ip)
		test_fatal("incorrect outer dst IP");
	/* Outer L4 Checks */
	udp = (void *)l3 + sizeof(*l3);
	if ((void *)udp + sizeof(*udp) > data_end)
		test_fatal("udp out of bounds");
	if (bpf_ntohs(udp->source) < MIN_GENEVE_SRC_PORT)
		test_fatal("unexpected src port on outer l4, got '%u' but expected >= '%u'",
			   bpf_ntohs(udp->source), MIN_GENEVE_SRC_PORT);

	if (bpf_ntohs(udp->dest) != TUNNEL_PORT)
		test_fatal("unexpected dest port on outer l4, expected '%u' but got '%u'",
			   TUNNEL_PORT, bpf_ntohs(udp->dest));
	geneve = (void *)udp + sizeof(*udp);
	if ((void *)geneve + sizeof(*geneve) > data_end)
		test_fatal("geneve out of bounds");
	gopt = (void *)geneve + sizeof(*geneve);
	if ((void *)gopt + sizeof(*gopt) > data_end)
		test_fatal("gopt out of bounds");
	if ((void *)gopt + geneve->opt_len * 4 > data_end)
		test_fatal("geneve opts out of bounds");
	inner_l2 = (void *)gopt + geneve->opt_len * 4;
	if ((void *)inner_l2 + sizeof(*inner_l2) > data_end)
		test_fatal("inner l2 out of bounds");
	inner_l3 = (void *)inner_l2 + sizeof(*inner_l2);
	if ((void *)inner_l3 + sizeof(*inner_l3) > data_end)
		test_fatal("inner l3 out of bounds");
	tcp_inner = (void *)inner_l3 + sizeof(*inner_l3);
	if ((void *)tcp_inner + sizeof(*tcp_inner) > data_end)
		test_fatal("tcp out of bounds");
	if (geneve->opt_len * 4 != sizeof(*gopt))
		test_fatal("geneve has unexpected opt length");
	if (gopt->hdr.opt_class != bpf_htons(GOOGLE_GENEVE_OPT_CLASS))
		test_fatal("geneve opt has unexpected class");
	if (gopt->hdr.type != test_ctx.hdr_type)
		test_fatal("geneve opt has unexpected type");
	if (gopt->hdr.length != test_ctx.hdr_length)
		test_fatal("geneve opt has unexpected length");
	if (gopt->addr != test_ctx.ip_opt)
		test_fatal("geneve opt has unexpected value");
	test_finish();
}
