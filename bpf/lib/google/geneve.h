#pragma once

#include "lib/google/hooks_common.h"

#ifdef ENABLE_GOOGLE_GENEVE

# include "lib/common.h"
# include "lib/jhash.h"
# include "lib/lb.h"
# include "lib/stubs.h"
# include "lib/pcap.h"

# if __ctx_is == __ctx_skb
#  include "lib/fib.h"
# endif /* __ctx_is == __ctx_skb */

# define GENEVE_VERSION		    0

# define GOOGLE_IPSEC_MODE_DISABLED 0
# define GOOGLE_IPSEC_MODE_SOFTWARE 1
# ifndef GOOGLE_IPSEC_MODE
#  define GOOGLE_IPSEC_MODE GOOGLE_IPSEC_MODE_DISABLED
# endif

# ifndef GOOGLE_GENEVE_METADATA
#  define GOOGLE_GENEVE_METADATA google_geneve_metadata
# endif

# ifndef GOOGLE_GENEVE_CURRENT_BPF_PROGRAM
#  define GOOGLE_GENEVE_CURRENT_BPF_PROGRAM google_geneve_cur_bpf_program
# endif

enum geneve_dir {
	GENEVE_DIR_INGRESS = 0,
	GENEVE_DIR_EGRESS = 1,
};

enum geneve_bpf_program_id {
	GENEVE_BPF_PROGRAM_ID_DEFAULT = 0, // Unknown program.
	GENEVE_BPF_PROGRAM_ID_TO_OVERLAY = 1,
	GENEVE_BPF_PROGRAM_ID_TO_NETDEV = 2,
	GENEVE_BPF_PROGRAM_ID_TO_HOST = 3,
	GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY = 4,
	GENEVE_BPF_PROGRAM_ID_FROM_LXC = 5,
	GENEVE_BPF_PROGRAM_ID_FROM_NETDEV = 6,
	GENEVE_BPF_PROGRAM_ID_FROM_NETDEV_XDP = 7,
	GENEVE_BPF_PROGRAM_ID_FROM_HOST = 8,
};

// The max number of Geneve options we are going to support as of today.
// NOTE: If we want support more than one geneve options to be specified in one packet,
// we may also want to make sure these geneve options are compatible with each other. This typically
// means the when one option calls ctx_store_meta() to store its data, it should not override
// other option's slot.
# define GENEVE_OPT_MAX_COUNT  1
// The max option length (in bytes) we are going to support due to verifier restriction
// Must be a multiplier of 4 bytes.
# define GENEVE_OPT_MAX_LENGTH 32
// The length of Geneve option data (only data part, excluding the geneve option header itself), divided by 4.
# define GENEVE_OPT_LENGTH_FIELD(opt_struct) \
	 ((__u8)((sizeof(opt_struct) - sizeof(struct geneve_opt_hdr)) / 4))

/* Geneve option used by Google.
 *
 * 0x0132-0x0135	Google LLC (According to [1])
 * 0x014B Cilium (According to [1])
 *
 * [1]: https://www.iana.org/assignments/nvo3/nvo3.xhtml#geneve-option-class
 */
# define GOOGLE_GENEVE_OPT_CLASS 0x0132
# define CILIUM_GENEVE_OPT_CLASS 0x014B

# ifdef ENABLE_IPV4

static __always_inline __u32 genevehdr_vni(const struct genevehdr *hdr)
{
	__u32 vni;

	if (!hdr)
		return 0;
	vni = (hdr->vni[0] << 16) + (hdr->vni[1] << 8) + hdr->vni[2];
	return vni;
}

struct geneve_encaphdr4 {
	struct iphdr ip;
	struct udphdr udp;
	struct genevehdr geneve;
} __packed;

struct geneve_metadata {
	// BPF tunnel key.
	struct bpf_tunnel_key tunnel_key;
	// Number of options included in opts[].
	__u8 opt_count;
	// Must align the field by 32 bytes.
	__u8 padding[3];
	/*
	 * Here we use an array to hold each geneve option, instead of a compressed memory
	 * section (meaning no gap between reach geneve options, like the geneve option
	 * data section in a packet). In this way we can access each option
	 * directly by using (i * GENEVE_OPT_MAX_LENGTH) as index.
	 *
	 * (GENEVE_OPT_MAX_LENGTH * GENEVE_OPT_MAX_COUNT) must by multiplier of 32 bytes,
	 * otherwise you will get "misaligned stack access off" verifier error.
	 */
	__u8 raw_opt_data[GENEVE_OPT_MAX_LENGTH * GENEVE_OPT_MAX_COUNT];
} __packed;

// GOOGLE_GENEVE_METADATA caches the geneve metadata from the current packet.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct geneve_metadata);
	/* One slot for ingress packet, one slot for egress packet.
	 * This is for the case when you received a ingressing GENEVE packet,
	 * decapsulated it, then you want to encapsulate it with different
	 * metadata (changed GENEVE option for example). You may not want to
	 * override the metadata extracted from the ingress packet, which
	 * may cause confusion.
	 */
	__uint(max_entries, 2);
} GOOGLE_GENEVE_METADATA __section_maps_btf;

// GOOGLE_GENEVE_METADATA caches the geneve metadata from the current packet.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, enum geneve_bpf_program_id);
	__uint(max_entries, 1);
} GOOGLE_GENEVE_CURRENT_BPF_PROGRAM __section_maps_btf;

/*
 * Bytes added to packets due to GENEVE encap. Here we picks the biggest GENEVE option
 * we are going to support and include it in the overhead.
 */
#  define GENEVE_MTU_OVERHEAD \
	  (sizeof(struct geneve_encaphdr4) + sizeof(struct geneve_dsr_opt6))

static __always_inline __u64 geneve_ctx_adjust_hroom_flags(void)
{
#  ifdef HAVE_CSUM_LEVEL
	return BPF_F_ADJ_ROOM_NO_CSUM_RESET;
#  else
	return 0;
#  endif
}

// Returns the length of the given geneve option as multiply of four bytes.
static __always_inline __u8 __geneve_opt_len(const void *opt)
{
	if (!opt)
		return 0;
	return (__u8)(sizeof(struct geneve_opt_hdr) / 4) +
	       (__u8)((const struct geneve_opt_hdr *)opt)->length;
}

// Returns if the given geneve option has critical bit set.
static __always_inline bool __geneve_opt_is_critical(const void *opt)
{
	if (!opt)
		return false;
	return !!(((const struct geneve_opt_hdr *)opt)->type &
		  GENEVE_OPT_TYPE_CRIT);
}

// Create a Geneve packet with given protocol type, VNI and Geneve options.
static __always_inline void
genevehdr_init(struct genevehdr *hdr, __u16 proto_type,
	       const struct geneve_metadata *metadata)
{
	__u8 opt_len = 0;
	__u8 critical = 0;
	__u32 vni = metadata->tunnel_key.tunnel_id;
	int i;

#  pragma unroll
	for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++) {
		if (i < metadata->opt_count) {
			struct geneve_opt_hdr *opt =
				(struct geneve_opt_hdr
					 *)(metadata->raw_opt_data +
					    i * GENEVE_OPT_MAX_LENGTH);

			opt_len += __geneve_opt_len(opt);
			if (!critical && __geneve_opt_is_critical(opt))
				critical = 1;
		}
	}

	*hdr = (const struct genevehdr){
			.ver = GENEVE_VERSION,
			.protocol_type = bpf_htons(proto_type),
			.critical = critical,
			.vni = {
					(__u8)(vni >> 16),
					(__u8)(vni >> 8),
					(__u8)vni,
				},
			.opt_len = opt_len,
	};
}

static __always_inline struct geneve_metadata *
geneve_get_metadata(const enum geneve_dir dir)
{
	// Here we expand the function call explicitly to make sure the compiler optimizes the memory access.
	switch (dir) {
	case GENEVE_DIR_INGRESS:
	{
		__u32 zero = 0;

		return (struct geneve_metadata *)
			map_lookup_elem(&GOOGLE_GENEVE_METADATA, &zero);
	} break;
	case GENEVE_DIR_EGRESS:
	{
		__u32 one = 1;

		return (struct geneve_metadata *)
			map_lookup_elem(&GOOGLE_GENEVE_METADATA, &one);
	} break;
	}
	return NULL;
}

static __always_inline int geneve_set_metadata(
	const struct geneve_metadata *metadata, const enum geneve_dir dir)
{
	if (!metadata)
		return DROP_INVALID;

	switch (dir) {
	case GENEVE_DIR_INGRESS:
	{
		__u32 zero = 0;

		if (map_update_elem(
			    &GOOGLE_GENEVE_METADATA, &zero, metadata, BPF_ANY) ==
		    0)
			return CTX_ACT_OK;
	} break;
	case GENEVE_DIR_EGRESS:
	{
		__u32 one = 1;

		if (map_update_elem(
			    &GOOGLE_GENEVE_METADATA, &one, metadata, BPF_ANY) ==
		    0)
			return CTX_ACT_OK;
	} break;
	}
	return DROP_WRITE_ERROR;
}

// geneve_clear_metadata clears both ingress and egress packet metadata.
static __always_inline int geneve_clear_metadata(const enum geneve_dir dir)
{
	const struct geneve_metadata metadata = { 0 };

	return geneve_set_metadata(&metadata, dir);
}

static __always_inline int
geneve_set_current_bpf_program(const enum geneve_bpf_program_id program_id)
{
	__u32 zero = 0;

	return map_update_elem(
		&GOOGLE_GENEVE_CURRENT_BPF_PROGRAM, &zero, &program_id, BPF_ANY);
}

static __always_inline enum geneve_bpf_program_id
geneve_get_current_bpf_program(void)
{
	__u32 zero = 0;
	const enum geneve_bpf_program_id *program_id =
		map_lookup_elem(&GOOGLE_GENEVE_CURRENT_BPF_PROGRAM, &zero);

	if (program_id)
		return *program_id;
	return GENEVE_BPF_PROGRAM_ID_DEFAULT;
}

static __always_inline bool
geneve_metadata_is_set(const struct geneve_metadata *metadata)
{
	return metadata && metadata->tunnel_key.remote_ipv4;
}

/*
 * geneve_get_option_from_metadata searches the metadata with given option class
 * and option type. If found, it returns the pointer to this option, otherwise
 * it returns NULL.
 */
static __always_inline const void *geneve_get_option_from_metadata(
	const struct geneve_metadata *metadata, __u16 opt_class, __u8 opt_type)
{
	int i;

	// opt_class stored in metadata is in network order.
	opt_class = bpf_htons(opt_class);
	if (!metadata || !metadata->opt_count)
		return NULL;

#  pragma unroll
	for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++) {
		const __u8 *opt_ptr =
			metadata->raw_opt_data + i * GENEVE_OPT_MAX_LENGTH;
		const struct geneve_opt_hdr *opt =
			(const struct geneve_opt_hdr *)opt_ptr;

		if (i >= metadata->opt_count)
			return NULL;
		if (opt && opt->opt_class == opt_class && opt->type == opt_type)
			return (const void *)opt;
	}
	return NULL;
}

/*
 * geneve_append_option_to_metadata appends the given GENEVE option to metadata.
 * The GENEVE option data will be copied, so we will still be able to fetch it
 * after tailcall.
 */
static __always_inline bool geneve_append_option_to_metadata(
	struct geneve_metadata *metadata, void *opt, __u32 opt_len)
{
	void *dst;
	__u32 copied_len = 0;

	if (!opt || !metadata || metadata->opt_count >= GENEVE_OPT_MAX_COUNT)
		return false;
	// Although we can infer the option length from option directly, but we
	// cannot use it here for some reason. Verifier will complain "w3 >>= 24: R3 32-bit pointer arithmetic prohibited",
	// even if we assign the value read from __geneve_opt_len() to variable and use
	// it later.
	// So here we ask invoker to pass in the option length instead, then we compare
	// if it has the same value as the option length read from the packet.
	if (opt_len > GENEVE_OPT_MAX_LENGTH ||
	    4 * (__u32)__geneve_opt_len(opt) != opt_len)
		return false;
	dst = metadata->raw_opt_data + metadata->opt_count * GENEVE_OPT_MAX_LENGTH;

	// memcpy() unfortunately requires the copy length to be static. So we cannot
	// just copy memory by opt_len here. As defined by the RFC, option length will always
	// be multiplier of 4, so we copy 4 bytes every time.
#  pragma unroll
	for (copied_len = 0; copied_len < GENEVE_OPT_MAX_LENGTH; copied_len += 4) {
		if (copied_len < opt_len) {
			memcpy(dst + copied_len, opt + copied_len, 4);
			if (copied_len + 4 == opt_len) {
				metadata->opt_count++;
				return true;
			}
		}
	}
	return false;
}

/* Decode the given Geneve option, store the found data into ctx.
 * Returns decoded Geneve option's length in bytes (header length included).
 * Returns 0 when decoding failed.
 */
static __always_inline __u32 geneve_decode_opt4(
	struct __ctx_buff *ctx, __u32 ctx_offset, __u8 *opt_data,
	__u32 opt_data_offset)
{
	struct geneve_opt_hdr opt;
	// Length of the geneve option we are parsing now.
	__u32 opt_len = 0;

	if (ctx_load_bytes(ctx, ctx_offset, &opt, sizeof(opt)) < 0)
		return 0;
	// There is no additional data after the option header. No need to proceed.
	if (opt.length == 0)
		return sizeof(opt);

	opt_len = 4 * (__u32)__geneve_opt_len(&opt);
	if (opt_len > GENEVE_OPT_MAX_LENGTH)
		return 0;
	if (opt_data_offset + opt_len >
	    (GENEVE_OPT_MAX_LENGTH * GENEVE_OPT_MAX_COUNT))
		return 0;
	if (ctx_load_bytes(ctx, ctx_offset, opt_data + opt_data_offset, opt_len) <
	    0)
		return 0;
	return opt_len;
}

/*
 * geneve_append_option_to_metadata adds the given option pointer(s) to geneve metadata.
 * It copies the option data to metadata, which should be stored in a percpu array map.
 * Note all existing options will be thrown away.
 */
static __always_inline int geneve_set_options_to_metadata(
	struct geneve_metadata *metadata, void *opt, __u32 opt_len)
{
	int i;
	__u32 parsed_len = 0;
	int ret;

	if (!metadata)
		return DROP_INVALID;
	// Clear all existing options.
	memset(metadata->raw_opt_data, 0, sizeof(metadata->raw_opt_data));
	if (!opt || !opt_len)
		return CTX_ACT_OK;
#  pragma unroll
	for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++) {
		if (parsed_len < opt_len) {
			void *cur_opt;
			__u32 cur_opt_len = 0;

			if (parsed_len + sizeof(struct geneve_opt_hdr) > opt_len)
				return DROP_INVALID;
			cur_opt = opt + parsed_len;
			cur_opt_len = 4 * (__u32)__geneve_opt_len(cur_opt);
			if (parsed_len + cur_opt_len > opt_len)
				return DROP_INVALID;
			ret = geneve_append_option_to_metadata(
				metadata, cur_opt, cur_opt_len);
			if (unlikely(ret < 0))
				return ret;

			parsed_len += cur_opt_len;
		}
	}

	if (parsed_len != opt_len)
		return DROP_INVALID;

	return CTX_ACT_OK;
}

/*
 * Replacement of the ctx_set_tunnel_key.
 */
static __always_inline int google_ctx_set_tunnel_key(
	struct __ctx_buff *ctx __maybe_unused, const struct bpf_tunnel_key *from,
	__u32 size, __u32 flags __maybe_unused)
{
	struct geneve_metadata *metadata = geneve_get_metadata(GENEVE_DIR_EGRESS);

	if (unlikely(!metadata || size > sizeof(struct bpf_tunnel_key)))
		return DROP_INVALID;
	memcpy(&metadata->tunnel_key, from, size);
	return geneve_set_metadata(metadata, GENEVE_DIR_EGRESS);
}

static __always_inline int google_ctx_set_tunnel_opt(
	struct __ctx_buff *ctx __maybe_unused, void *opt, __u32 size)
{
	struct geneve_metadata *metadata = geneve_get_metadata(GENEVE_DIR_EGRESS);
	int ret;

	if (unlikely(!metadata))
		return DROP_INVALID;
	ret = geneve_set_options_to_metadata(metadata, opt, size);
	if (unlikely(ret < 0))
		return ret;
	return geneve_set_metadata(metadata, GENEVE_DIR_EGRESS);
}

/*
 * Flow hash from 5-tuple if ports are available. Otherwise, hash using 3-tuple.
 */
static __always_inline __u32
geneve_flow_hash4(struct __ctx_buff *ctx, struct iphdr *ip4)
{
	struct ipv4_ct_tuple l4tuple = { 0 };
	int l4_offset = 0;
	__u32 a, b, c;
	int ret __maybe_unused;

	// We want to support any protocol here, so no need to check return code here.
	// The 3-tuple (saddr, daddr, protocol) should be extracted regardless.
	ret = lb4_extract_tuple(ctx, ip4, ETH_HLEN, &l4_offset, &l4tuple);
	a = l4tuple.saddr;
	b = l4tuple.daddr;
	c = l4tuple.nexthdr;
	__jhash_mix(a, b, c);
	a += HASH_INIT4_SEED;
	b += ((__u32)l4tuple.dport << 16) | l4tuple.sport;
	__jhash_final(a, b, c);
	return c;
}

/*
 * geneve_encaphdr4_size calculates the total size of the given Geneve encap header in bytes.
 * This includes size of outer IP header, outer UDP header and Geneve header with options.
 */
static __always_inline __u16 geneve_encaphdr4_size(struct geneve_encaphdr4 *hdr)
{
	if (!hdr)
		return 0;
	return sizeof(struct geneve_encaphdr4) + 4 * (__u16)hdr->geneve.opt_len;
}

/* Check if the packet is a BPF geneve packet.
 * This doesn't really verify the Geneve header. It merely checks if the
 * length of the header is big enough to include IP+UDP+Geneve header,
 * and the destination port in outer UDP header matches what we expect.
 */
static __always_inline bool
geneve_is_encapped(struct __ctx_buff *ctx, const struct iphdr *ip4)
{
	__be16 dport;
	int l4_offset = ETH_HLEN + ipv4_hdrlen(ip4);
	int dport_off = l4_offset + UDP_DPORT_OFF;
	struct genevehdr geneve;
	int ret = 0;

	if (ip4->protocol != IPPROTO_UDP)
		return false;
	ret = l4_load_port(ctx, dport_off, &dport);
	if (IS_ERR(ret))
		return false;
	if (bpf_ntohs(ip4->tot_len) < sizeof(struct geneve_encaphdr4))
		return false;
	if (bpf_ntohs(dport) != TUNNEL_PORT)
		return false;
	if (ctx_load_bytes(ctx, l4_offset + sizeof(struct udphdr), &geneve,
			   sizeof(geneve)) < 0)
		return false;
#  if __ctx_is == __ctx_xdp
	if (geneve.opt_len) {
		// Punt packets with GENEVE options to TC, as currently there is no
		// mechanism to pass the GENEVE option data from XDP to TC.
		struct geneve_opt_hdr opt;

		if (ctx_load_bytes(
			    ctx,
			    l4_offset + sizeof(struct udphdr) +
				    sizeof(struct genevehdr),
			    &opt, sizeof(opt)) < 0)
			return false;
		switch (opt.opt_class) {
#   if defined(ENABLE_DSR) && DSR_ENCAP_MODE == DSR_ENCAP_GENEVE
		case bpf_htons(DSR_GENEVE_OPT_CLASS):
			switch (opt.type) {
			case DSR_GENEVE_OPT_TYPE:
				// DSR uses up five metadata slots by it self, so we do not have extra space to pass information like VNI
				// from XDP to TC. In this case, we are going to decap in TC. DSR only set GENEVE option in the first
				// TCP SYN packet, so this should not impact performance (See dsr_set_opt4() in nodeport.h).
				return false;
			}
			break;
#   endif
		default:
			/* For all unsupported GENEVE option, by default we are going
			 * let TC program to handle them, as there is no ideal way for
			 * us to pass metadata from XDP to TC. The space xdp_adjust_meta()
			 * provides is too small and limited.
			 */
			return false;
		}
	}
#  endif
	if (geneve.protocol_type != bpf_htons(ETH_P_IP))
		return false;
	return true;
}

static __always_inline bool
geneve_is_encapped_to_node4(struct __ctx_buff *ctx, const struct iphdr *ip4)
{
	// If destination is not this node, return false.
	if (ip4->daddr != IPV4_DIRECT_ROUTING)
		return false;
	return geneve_is_encapped(ctx, ip4);
}

static __always_inline bool
geneve_is_encapped_from_node4(struct __ctx_buff *ctx, const struct iphdr *ip4)
{
	// If source is not this node, return false.
	if (ip4->saddr != IPV4_DIRECT_ROUTING)
		return false;
	return geneve_is_encapped(ctx, ip4);
}

// Encapsulates the given ctx_buff with Geneve.
// The encapsulated header will be stored to `hdr` as well.
static __always_inline int
geneve_encap4(struct __ctx_buff *ctx, struct geneve_metadata *metadata,
	      struct geneve_encaphdr4 *hdr)
{
	__u64 flags __maybe_unused;
	__u16 sport;
	struct iphdr *ip4;
	struct ethhdr *eth;
	void *data, *data_end;
	__u16 hdr_len = 0;
	__u32 encoded_opt_len = 0;
	int i;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	eth = data;
	genevehdr_init(&hdr->geneve, ETH_P_IP, metadata);
	hdr_len = geneve_encaphdr4_size(hdr);

	/* https://datatracker.ietf.org/doc/html/rfc8926#section-3.3:
	 * To encourage an even distribution of flows across multiple links, the source port SHOULD be
	 * calculated using a hash of the encapsulated packet headers using, for example, a traditional 5-tuple.
	 *
	 * The hash is ORed with 0x8000 to make the port high enough to not conflict with priveleged ports.
	 * Set LSB to 1 (odd port) for reply traffic.
	 * Set LSB to 0 (even port) for non-reply traffic.
	 */
	sport = (csum_fold(geneve_flow_hash4(ctx, ip4)) & 0xFFFE) | 0x8000;
	hdr->udp.source = bpf_htons(sport);
	hdr->udp.dest = bpf_htons(TUNNEL_PORT);
	hdr->udp.len = bpf_htons(
		bpf_ntohs(ip4->tot_len) + hdr_len - sizeof(struct iphdr));
	hdr->udp.check = 0; /* we use BPF_F_ZERO_CSUM_TX */

	hdr->ip.version = IPVERSION;
	hdr->ip.ttl = IPDEFTTL;
	hdr->ip.tos = ip4->tos;
	hdr->ip.id = ip4->id;
	if (metadata->tunnel_key.local_ipv4)
		hdr->ip.saddr = bpf_htonl(metadata->tunnel_key.local_ipv4);
	else
		hdr->ip.saddr = IPV4_DIRECT_ROUTING;
	hdr->ip.daddr = bpf_htonl(metadata->tunnel_key.remote_ipv4);
	hdr->ip.protocol = IPPROTO_UDP;
	hdr->ip.ihl = sizeof(struct iphdr) >> 2;
	hdr->ip.tot_len = bpf_htons(bpf_ntohs(ip4->tot_len) + hdr_len);
	hdr->ip.check =
		csum_fold(csum_diff(NULL, 0, &hdr->ip, sizeof(hdr->ip), 0));

	eth->h_proto = bpf_htons(ETH_P_IP);

	flags = geneve_ctx_adjust_hroom_flags();
	flags |= BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
	if (ip4->protocol == IPPROTO_UDP) {
		// UDP GSO must have BPF_F_ADJ_ROOM_FIXED_GSO.
		flags |= BPF_F_ADJ_ROOM_FIXED_GSO;
	}

	if (ctx_adjust_hroom(ctx, hdr_len, BPF_ADJ_ROOM_MAC, flags))
		return DROP_INVALID;
	if (ctx_store_bytes(ctx, ETH_HLEN, hdr, sizeof(struct geneve_encaphdr4),
			    BPF_F_INVALIDATE_HASH) < 0)
		return DROP_INVALID;
	if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	// Start to store geneve options.
#  pragma unroll
	for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++) {
		if (i < metadata->opt_count) {
			struct geneve_opt_hdr *opt =
				(struct geneve_opt_hdr
					 *)(metadata->raw_opt_data +
					    i * GENEVE_OPT_MAX_LENGTH);
			__u32 opt_len = 4 * (__u32)__geneve_opt_len(opt);

			// Skip if the option length is too long.
			if (opt_len > GENEVE_OPT_MAX_LENGTH)
				return DROP_INVALID;
			if (data + ETH_HLEN + sizeof(struct geneve_encaphdr4) +
				    encoded_opt_len + opt_len >
			    data_end)
				return DROP_INVALID;

#  if __ctx_is == __ctx_skb
			if (ctx_store_bytes(
				    ctx,
				    ETH_HLEN + sizeof(struct geneve_encaphdr4) +
					    encoded_opt_len,
				    opt, opt_len, BPF_F_INVALIDATE_HASH) < 0)
				return DROP_INVALID;
#  elif __ctx_is == __ctx_xdp
			{
				// In XDP, ctx_store_bytes uses memcpy which requires constant length.
				// Copy manually byte-by-byte (or 4-byte chunks).
				// opt_len is max (32 * 1) * 4 = 128 bytes.
				void *pkt_data =
					data + ETH_HLEN +
					sizeof(struct geneve_encaphdr4) +
					encoded_opt_len;
				__u32 k;

				if (pkt_data + opt_len > data_end)
					return DROP_INVALID;

#   pragma unroll
				for (k = 0; k < GENEVE_OPT_MAX_LENGTH; k++) {
					if (k < opt_len) {
						if (pkt_data + k + 1 > data_end)
							break;
						((__u8 *)pkt_data)[k] =
							((__u8 *)opt)[k];
					}
				}
			}
#  endif

			encoded_opt_len += opt_len;
		}
	}
	if (sizeof(struct geneve_encaphdr4) + encoded_opt_len != hdr_len)
		return DROP_INVALID;
	return CTX_ACT_REDIRECT;
}

static __always_inline int
geneve_decap4(struct __ctx_buff *ctx, struct geneve_metadata *metadata)
{
	struct geneve_encaphdr4 hdr = { 0 };
	__u16 hdr_len = 0;

	if (ctx_load_bytes(ctx, ETH_HLEN, &hdr, sizeof(hdr)) < 0)
		return DROP_INVALID;

	metadata->tunnel_key.local_ipv4 = hdr.ip.saddr;
	metadata->tunnel_key.remote_ipv4 = hdr.ip.daddr;
	metadata->tunnel_key.tunnel_id = genevehdr_vni(&hdr.geneve);
	ctx_set_xfer(ctx, XFER_PKT_GOOGLE_BPF_GENEVE);
	hdr_len = geneve_encaphdr4_size(&hdr);

	// Extract Geneve options one by one.
	if (hdr.geneve.opt_len > 0) {
		__u32 total_opt_len = 4 * (__u32)hdr.geneve.opt_len;
		__u32 decoded_opt_len = 0;
		int i;

#  pragma unroll
		for (i = 0; i < GENEVE_OPT_MAX_COUNT; i++) {
			if (decoded_opt_len < total_opt_len) {
				__u32 opt_len = geneve_decode_opt4(
					ctx,
					ETH_HLEN + sizeof(hdr) + decoded_opt_len,
					metadata->raw_opt_data,
					i * GENEVE_OPT_MAX_LENGTH);

				// Drop the packet when there is pending option to be decoded, but the decode function
				// returns error. The packet is malformed in this case.
				if (!opt_len)
					return DROP_INVALID;
				decoded_opt_len += opt_len;
				metadata->opt_count++;
			}
		}
		// Total option length in Geneve packet header doesn't match the sum of option
		// data length we found.
		if (decoded_opt_len != total_opt_len)
			return DROP_INVALID;
	}

	// Store geneve metadata.
	if (geneve_set_metadata(metadata, GENEVE_DIR_INGRESS) < 0)
		return DROP_INVALID;

	// Remove geneve header from the packet and adjust the packet head room.
#  if __ctx_is == __ctx_skb
	{
		__u64 flags =
			geneve_ctx_adjust_hroom_flags() | BPF_F_ADJ_ROOM_FIXED_GSO;

		if (ctx_adjust_hroom(ctx, -(__s32)hdr_len, BPF_ADJ_ROOM_MAC, flags))
			return DROP_INVALID;
	}
#  elif __ctx_is == __ctx_xdp
	{
		// The cilium ctx_adjust_hroom for XDP is pretty hacky, it only supports
		// adjusting at BPF_ADJ_ROOM_NET with a limited selection of adjustment size.
		// Therefore we adjust head by ourselves here.
		struct ethhdr eth;

		if (ctx_load_bytes(ctx, 0, &eth, ETH_HLEN) < 0)
			return DROP_INVALID;
		if (xdp_adjust_head(ctx, (__s32)hdr_len))
			return DROP_INVALID;
		if (ctx_store_bytes(ctx, 0, &eth, ETH_HLEN, BPF_F_INVALIDATE_HASH) <
		    0)
			return DROP_INVALID;
	}
#  else
	return DROP_INVALID;
#  endif

	{
		void *data, *data_end;
		struct iphdr *ip4;
		// We need to pull the skb once after decapsulation to make sure the new IP header
		// is linear in memory.
		// This step is no-op in XDP as it's already linear there.
		if (!revalidate_data_pull(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
	}
	return CTX_ACT_OK;
}

/* geneve_try_decap4 tries to decapsulate the incoming packet as a GENEVE packet.
 * Returns HOOK_ACT_CONTINUE when:
 *    - when the given packet is not a geneve packet;
 *    - or we do not plan to decapsulate in this stage (e.g. we do not decap certain geneve packets in XDP)
 * Other return code is also possible.
 */
static __always_inline int geneve_try_decap4(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;
	if (!geneve_is_encapped_to_node4(ctx, ip4))
		return HOOK_ACT_CONTINUE;

	return tail_call_internal(ctx, CILIUM_CALL_GOOGLE_IPV4_GENEVE_DECAP, NULL);
}

/*
 * A tail call which decapsulate the given GENEVE IPv4 packet.
 * When the geneve decapsulation is successful, geneve_get_current_bpf_program() will be
 * set to GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY, then the problem will be tail-called back
 * to the from-lxc/from-netdev section entry.
 * Return DROP_INVALID when the given packet is not a GENEVE packet, it will be dropped.
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_GOOGLE_IPV4_GENEVE_DECAP)
int tail_geneve_decap4(struct __ctx_buff *ctx)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct geneve_metadata metadata = { 0 };
	__u32 src_sec_identity = 0;
	__s8 ext_err = 0;
	int ret;

	ret = geneve_decap4(ctx, &metadata);
	if (IS_ERR(ret))
		goto out;
	if (!revalidate_data(ctx, &data, &data_end, &ip4)) {
		ret = DROP_INVALID;
		goto out;
	}
	// After we successfully decapped the packet, we consider we are in bpf_overlay now.
	if (geneve_set_current_bpf_program(GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY) <
	    0) {
		ret = DROP_WRITE_ERROR;
		goto out;
	}

	{
		struct remote_endpoint_info *info;
		__u16 proto;

#  ifndef ENABLE_HIGH_SCALE_IPCACHE
		/* preserve skb->cb for hs-ipcache, from-netdev is passing info */
		bpf_clear_meta(ctx);
#  endif
		ctx_skip_nodeport_clear(ctx);

		if (!validate_ethertype(ctx, &proto)) {
			/* Pass unknown traffic to the stack */
			ret = CTX_ACT_OK;
			goto out;
		}

		cilium_dbg(ctx, DBG_DECAP, metadata.tunnel_key.tunnel_id,
			   metadata.tunnel_key.tunnel_label);

		/* Lookup source identity here.
		 * In OSS implementation, this value is from get_id_from_tunnel_id() (see bpf_overlay.c)
		 * However, in GDC-ag 1.13, the tunnel_id is always zero (default VPC ID).
		 * This means we cannot trust the source identity from tunnel ID here.
		 */
		info = lookup_ip4_remote_endpoint(ip4->saddr, 0);
		if (info)
			src_sec_identity = info->sec_identity;

		/* Any node encapsulating will map any HOST_ID source to be
		 * presented as REMOTE_NODE_ID, therefore any attempt to signal
		 * HOST_ID as source from a remote node can be dropped.
		 */
		if (src_sec_identity == HOST_ID) {
			ret = DROP_INVALID_IDENTITY;
			goto out;
		}

		/* Store the identity read from VNI to metadata, OSS Cilium
		 * is using CB_SRC_LABEL to store source identity.
		 * However, also note that this field may not be used in bpf_host
		 * which will explicitly call resolve_srcid_ipv4() in
		 * do_netdev() to resolve the source identity.
		 */
		ctx_store_meta(ctx, CB_SRC_LABEL, src_sec_identity);
	}

	/* Prevent invalid size of register spill on data_end (verifier error). */
	data = NULL;
	data_end = NULL;

	{
		enum trace_point obs_point = TRACE_FROM_OVERLAY;

#  if GOOGLE_IPSEC_MODE == GOOGLE_IPSEC_MODE_SOFTWARE
		obs_point = TRACE_FROM_STACK;
#  endif
		send_trace_notify(
			ctx, obs_point, src_sec_identity, UNKNOWN_ID,
			TRACE_EP_ID_UNKNOWN, ctx->ingress_ifindex,
			TRACE_REASON_UNKNOWN, TRACE_PAYLOAD_LEN);
	}

	ret = HOOK_ACT_CONTINUE;
	if (geneve_set_metadata(&metadata, GENEVE_DIR_INGRESS) < 0)
		ret = DROP_WRITE_ERROR;
out:
	if (ret != HOOK_ACT_CONTINUE && IS_ERR(ret))
		return send_drop_notify_error_ext(
			ctx, src_sec_identity, ret, ext_err, CTX_ACT_DROP,
			METRIC_INGRESS);

#  if __ctx_is == __ctx_xdp
	// For XDP, we just exit here, and the packet will be processed in TC later.
	// Note since we have tail-called to here, we cannot simply return HOOK_ACT_CONTINUE.
	ctx_move_xfer(ctx);
	return CTX_ACT_OK;
#  else
	// The packet has been successfully decapped, recirculate the packet.
	return tail_call_internal(ctx, CILIUM_CALL_IPV4_FROM_NETDEV, NULL);
#  endif
}

# endif /* ENABLE_IPV4 */

/*
 * Redirect encapped packet to direct routing device.
 * When IPSec is enabled, this will return CTX_ACT_OK to make sure the packet go out via kernel.
 */
static __always_inline int __google_encap_redirect_v4(
	struct __ctx_buff *ctx, __u32 dstid __maybe_unused,
	int ifindex __maybe_unused, const struct trace_ctx *trace __maybe_unused)
{
	int ret = DROP_WRITE_ERROR;

# if defined(ENABLE_IPV4) && defined(ENCAP_IFINDEX)
	if (ifindex == ENCAP_IFINDEX) {
		// ifindex typically should always be ENCAP_IFINDEX for the packet to be redirected to the overlay interface.
		// However, ifindex is set to zero in some cases in encap.h when __ctx_is == __ctx_xdp
#  if __ctx_is == __ctx_skb
#   if GOOGLE_IPSEC_MODE == GOOGLE_IPSEC_MODE_DISABLED
		void *data, *data_end;
		struct iphdr *ip4;
		__s8 ext_err = 0;
		int oif;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;

		ifindex = DIRECT_ROUTING_DEV_IFINDEX;
		ret = fib_redirect_v4(ctx, ETH_HLEN, ip4, true, false, &ext_err, &oif);
		goto to_redirect;
#   else  /* GOOGLE_IPSEC_MODE */
		// If IPSec is enabled, send the packet back to kernel for IPSec encryption.
		send_trace_notify(
			ctx, TRACE_TO_STACK, SECLABEL, dstid, 0, ifindex,
			TRACE_REASON_UNKNOWN, 0);
		return CTX_ACT_OK;
#   endif /* GOOGLE_IPSEC_MODE */
#  else	  /* __ctx_is == __ctx_xdp */
		ctx_move_xfer(ctx);
		ifindex = DIRECT_ROUTING_DEV_IFINDEX;
		ret = ctx_redirect(ctx, ifindex, 0);
		goto to_redirect;
#  endif  /* __ctx_is == __ctx_skb */
	}
# else
	// IPv6 is not supported.
	__throw_build_bug();
# endif /* ENABLE_IPV4 */

__maybe_unused to_redirect:
	if (likely(ret == CTX_ACT_REDIRECT)) {
		cilium_capture_out(ctx);
		send_trace_notify(
			ctx, TRACE_TO_NETWORK, SECLABEL, dstid, 0, ifindex,
			TRACE_REASON_UNKNOWN, 0);
	} else if (IS_ERR(ret))
		return send_drop_notify_error(
			ctx, 0, ret, CTX_ACT_DROP, METRIC_EGRESS);
	return ret;
}

/*
 * A replacement of the original ctx_get_tunnel_key()
 */
static __always_inline __maybe_unused int google_ctx_get_tunnel_key(
	struct __ctx_buff *ctx __maybe_unused, struct bpf_tunnel_key *to,
	__u32 size, __u32 flags __maybe_unused)
{
	const enum geneve_bpf_program_id program_id =
		geneve_get_current_bpf_program();
	struct geneve_metadata *metadata;

	// Align with kernel behavior, get corresponding metadata for different direction.
	if (program_id == GENEVE_BPF_PROGRAM_ID_TO_OVERLAY)
		metadata = geneve_get_metadata(GENEVE_DIR_EGRESS);
	else
		metadata = geneve_get_metadata(GENEVE_DIR_INGRESS);
	if (!metadata)
		return DROP_INVALID;
	if (size > sizeof(struct bpf_tunnel_key))
		return DROP_INVALID;
	memcpy(to, &metadata->tunnel_key, size);
	return CTX_ACT_OK;
}

/*
 * A replacement of the original ctx_set_encap_info()
 */
static __always_inline __maybe_unused int google_ctx_set_encap_info(
	struct __ctx_buff *ctx __maybe_unused, __u32 src_ip,
	__be16 src_port __maybe_unused, __u32 node_id, __u32 seclabel,
	__u32 vni __maybe_unused, void *opt, __u32 opt_len)
{
	struct geneve_metadata metadata = { 0 };
	int ret;

# ifdef ENABLE_VTEP
	if (vni != NOT_VTEP_DST)
		metadata.tunnel_key.tunnel_id = get_tunnel_id(vni);
	else
# endif /* ENABLE_VTEP */
		metadata.tunnel_key.tunnel_id = get_tunnel_id(seclabel);

	if (src_ip != 0)
		metadata.tunnel_key.local_ipv4 = bpf_ntohl(src_ip);
	metadata.tunnel_key.remote_ipv4 = node_id;
	metadata.tunnel_key.tunnel_ttl = IPDEFTTL;

	// Set geneve options
	ret = geneve_set_options_to_metadata(&metadata, opt, opt_len);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;
	// Persist GENEVE metadata to map.
	ret = geneve_set_metadata(&metadata, GENEVE_DIR_EGRESS);
	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;

	return CTX_ACT_REDIRECT;
}

static __always_inline int google_ctx_redirect_to_overlay(struct __ctx_buff *ctx)
{
	int ret = geneve_set_current_bpf_program(GENEVE_BPF_PROGRAM_ID_TO_OVERLAY);

	if (unlikely(ret < 0))
		return DROP_WRITE_ERROR;
	return tail_call_internal(ctx, CILIUM_CALL_GOOGLE_IPV4_GENEVE_ENCAP, NULL);
}

/*
 * Replacement of ctx_redirect() when eBPF GENEVE is on.
 */
static __always_inline int google_geneve_ctx_redirect(
	struct __ctx_buff *ctx __maybe_unused, int ifindex, const __u32 flags)
{
	const enum geneve_bpf_program_id program_id =
		geneve_get_current_bpf_program();

	/*
	 * Only do the following when we have not gone through the overlay redirection
	 * logic, and the packet is heading to the egress of the overlay interface.
	 * This makes sure the packet is not going through a loop.
	 * The loop may happen in __google_encap_redirect_v4()/fib_redirect_v4(), where
	 * ctx_redirect() is called again.
	 */
# ifdef ENCAP_IFINDEX
	if (program_id != GENEVE_BPF_PROGRAM_ID_TO_OVERLAY &&
	    ifindex == ENCAP_IFINDEX && flags == 0)
		return google_ctx_redirect_to_overlay(ctx);
# endif

	// The original redirection logic for both XDP and TC.
# if __ctx_is == __ctx_xdp
	if ((__u32)ifindex == ctx->ingress_ifindex)
		return XDP_TX;
# endif
	return redirect(ifindex, flags);
}

/*
 * A tailcall which encapsulate the packet into a geneve packet,
 * then sending it out via DIRECT ROUTING DEVICE by using bpf_redirect().
 *
 * Note:
 * The packet may go through CILIUM_CALL_IPV4_NODEPORT_NAT_FWD in this function
 * for SNAT/Conntracking etc., where the packet will recirculate to the interface before encapsulation.
 * We need to make sure the GENEVE encap hook (i.e. geneve_redirect_to_overlay_if_encapped) is invoked
 * in the CILIUM_CALL_IPV4_FROM_NETDEV __section_tail in the corresponding bpf program,
 * so that the packet will be back here for encapsulation.
 */
__section_tail(CILIUM_MAP_CALLS, CILIUM_CALL_GOOGLE_IPV4_GENEVE_ENCAP)
int tail_geneve_encap_and_redirect_to_overlay(
	struct __ctx_buff *ctx)
{
	const enum geneve_bpf_program_id program_id =
		geneve_get_current_bpf_program();
	struct geneve_metadata *metadata;
	bool snat_done __maybe_unused = ctx_snat_done(ctx);
	struct trace_ctx __maybe_unused trace;
	__u32 src_sec_identity = UNKNOWN_ID;
	int ret = CTX_ACT_OK;
	__be16 __maybe_unused proto = 0;
	__s8 ext_err = 0;
	struct geneve_encaphdr4 hdr __maybe_unused = { 0 };

	/* We only redirect packet after we enter the overlay domain.
	 * A packet doesn't have correct metadata should not arrive here.
	 */
	if (program_id != GENEVE_BPF_PROGRAM_ID_TO_OVERLAY)
		return DROP_INVALID;
	metadata = geneve_get_metadata(GENEVE_DIR_EGRESS);
	if (!geneve_metadata_is_set(metadata))
		return DROP_INVALID;

	/* Load the ethertype just once: */
	validate_ethertype(ctx, &proto);

	// Not support by GDC-ag.
# if defined(ENABLE_BANDWIDTH_MANAGER) || defined(ENABLE_CLUSTER_AWARE_ADDRESSING)
	__throw_build_bug();
# endif

	/* We might see some unexpected packets without tunnel_key (eg. IPv6 ND).
	 * No need to worry, the geneve/vxlan kernel drivers will drop them.
	 */
	src_sec_identity = get_id_from_tunnel_id(
		metadata->tunnel_key.tunnel_id, ctx_get_protocol(ctx));

	// Reset VNI.
	metadata->tunnel_key.tunnel_id = 0;

	set_identity_mark(ctx, src_sec_identity, MARK_MAGIC_OVERLAY);

# ifdef ENABLE_NODEPORT
	if (snat_done)
		goto out;

	/* handle_nat_fwd from nodeport.h start */
	ctx_store_meta(ctx, CB_NAT_FLAGS, 0);
	// Clear cluster ID as we don't use it.
	ctx_store_meta(ctx, CB_CLUSTER_ID_EGRESS, 0);

	switch (proto) {
#  ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		/*
		 * Although CILIUM_CALL_IPV4_NODEPORT_NAT_FWD __section_tail is defined nodeport.h,
		 * and we cannot import nodeport.h in this file as it will cause a dependency loop
		 * (google/geneve.h -> nodeport.h -> nat.h -> encap.h -> google/geneve.h), we are
		 * pretty sure nodeport.h will be included later when ENABLE_NODEPORT is defined.
		 * Therefore the tailcall here will succeed.
		 * The program will return to here again later with `snat_done` set.
		 */
		ret = tail_call_internal(
			ctx, CILIUM_CALL_IPV4_NODEPORT_NAT_FWD, NULL);
		break;
#  endif /* ENABLE_IPV4 */
	default:
		build_bug_on(!(NODEPORT_PORT_MIN_NAT < NODEPORT_PORT_MAX_NAT));
		build_bug_on(!(NODEPORT_PORT_MIN < NODEPORT_PORT_MAX));
		build_bug_on(!(NODEPORT_PORT_MAX < NODEPORT_PORT_MIN_NAT));
		break;
	}
	if (IS_ERR(ret))
		return send_drop_notify_error_ext(
			ctx, src_sec_identity, ret, ext_err, CTX_ACT_DROP,
			METRIC_EGRESS);
	/* handle_nat_fwd from nodeport.h end */

out:
# endif
	// At this point we should consider the packet is already heading out, i.e. this is
	// equivalent to returning CTX_ACT_OK in cil_to_overlay. The belows steps are the
	// translations of the original kernel steps.

	// Do GENEVE encapsulation with options.
# ifdef ENABLE_IPV4
	ret = geneve_encap4(ctx, metadata, &hdr);
	if (IS_ERR(ret))
		return ret;
# else
	// IPv6 is not supported yet.
	__throw_build_bug();
# endif /* ENABLE_IPV4 */

	if (IS_ERR(ret))
		return send_drop_notify_error_ext(
			ctx, src_sec_identity, ret, ext_err, CTX_ACT_DROP,
			METRIC_EGRESS);

	// Redirect packet to eth0 (or kernel when IPSec mode == software).
	return __google_encap_redirect_v4(ctx, 0, ENCAP_IFINDEX, &trace);
}

/*
 * Check GENEVE metadata on egress direction is set. If yes, send the packet
 * out via DIRECT ROUTING interface.
 */
static __always_inline int
geneve_redirect_to_overlay_if_encapped(struct __ctx_buff *ctx)
{
	const enum geneve_bpf_program_id program_id =
		geneve_get_current_bpf_program();
	struct geneve_metadata *metadata;

	// We only redirect packet after we enter the overlay domain.
	if (program_id != GENEVE_BPF_PROGRAM_ID_TO_OVERLAY)
		return HOOK_ACT_CONTINUE;
	metadata = geneve_get_metadata(GENEVE_DIR_EGRESS);
	if (!geneve_metadata_is_set(metadata))
		return HOOK_ACT_CONTINUE;

	return tail_call_internal(ctx, CILIUM_CALL_GOOGLE_IPV4_GENEVE_ENCAP, NULL);
}

static __always_inline int geneve_reset_state(void)
{
	// Clear existing metadata from previous packets.
	if (geneve_clear_metadata(GENEVE_DIR_INGRESS) < 0 ||
	    geneve_clear_metadata(GENEVE_DIR_EGRESS) < 0)
		return DROP_WRITE_ERROR;
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_ctr_egress_start4(void)
{
	int ret = geneve_reset_state();

	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	if (geneve_set_current_bpf_program(GENEVE_BPF_PROGRAM_ID_FROM_LXC) < 0)
		return DROP_WRITE_ERROR;
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_netdev_ingress_fwd4(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_netdev_ingress_fwd4_ctx *stage_ctx)
{
	/* If this packet is decapsulated from GENEVE tunnel,
	 * then skip the multi-nic and host routing logic.
	 */
	stage_ctx->__common.go_to_endpoint =
		geneve_get_current_bpf_program() ==
		GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY;

	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_netdev_ingress_fwd4_ipsec(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_host_ingress_fwd4_ctx_common *stage_ctx_common __maybe_unused)
{
# if GOOGLE_IPSEC_MODE == GOOGLE_IPSEC_MODE_SOFTWARE
	// In some situation, e.g., the packet got recirculated after IPSec decryption,
	// it may be marked as OTHERHOST. We need to change it to HOST so that kernel won't drop it.
	ctx_change_type(ctx, PACKET_HOST);

	/* After geneve tunnel is terminated in cilium, ebpf lacks the API to
	 * "scrub" the SKB to remove stale XFRM data(skb->sp). This impacts traffic
	 * destined to node. To workaround this we redirect locally destined traffic
	 * to cilium host(which forces the kernel to scrub) when N2N encryption is
	 * enabled.
	 * TODO(b/383158433): Revert this change once HW offload is available.
	 */
	if (geneve_get_current_bpf_program() == GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY &&
	    stage_ctx_common->ep && stage_ctx_common->ep->flags & ENDPOINT_F_HOST) {
		union macaddr router_mac = THIS_INTERFACE_MAC;
		union macaddr host_mac = HOST_IFINDEX_MAC;
		void *data, *data_end;
		struct iphdr *ip4;
		int ret;

		if (!revalidate_data(ctx, &data, &data_end, &ip4))
			return DROP_INVALID;
		ret = ipv4_l3(ctx, ETH_HLEN, (__u8 *)&router_mac.addr,
			      (__u8 *)&host_mac.addr, ip4);
		if (ret != CTX_ACT_OK)
			return ret;

		return ctx_redirect(ctx, HOST_IFINDEX, 0);
	}
# endif
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
goog_geneve_pre_netdev_ingress_start(struct __ctx_buff *ctx)
{
	int ret = geneve_reset_state();
	__u32 flags = ctx_get_xfer(ctx, XFER_FLAGS);

	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	if (flags & XFER_PKT_GOOGLE_BPF_GENEVE) {
		if (geneve_set_current_bpf_program(
			    GENEVE_BPF_PROGRAM_ID_FROM_OVERLAY) < 0)
			return DROP_WRITE_ERROR;
	} else {
		if (geneve_set_current_bpf_program(
			    GENEVE_BPF_PROGRAM_ID_FROM_NETDEV) < 0)
			return DROP_WRITE_ERROR;

		ret = geneve_try_decap4(ctx);
		if (ret != HOOK_ACT_CONTINUE)
			return ret;
	}

	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_host_ingress_start(void)
{
	int ret = geneve_reset_state();

	if (ret != HOOK_ACT_CONTINUE)
		return ret;
	if (geneve_set_current_bpf_program(GENEVE_BPF_PROGRAM_ID_FROM_HOST) < 0)
		return DROP_WRITE_ERROR;

	return HOOK_ACT_CONTINUE;
}

#else /* ENABLE_GOOGLE_GENEVE */

/*
 * When Google geneve is not enabled, this function is basicly doing
 * what the original ctx_redirect() is doing.
 */
static __always_inline int google_geneve_ctx_redirect(
	struct __ctx_buff *ctx __maybe_unused, int ifindex, const __u32 flags)
{
# if __ctx_is == __ctx_xdp
	if ((__u32)ifindex == ctx->ingress_ifindex)
		return XDP_TX;
# endif
	return redirect(ifindex, flags);
}

static __always_inline int geneve_reset_state(void)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_ctr_egress_start4(void)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
geneve_redirect_to_overlay_if_encapped(struct __ctx_buff *ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_netdev_ingress_fwd4(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_netdev_ingress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_host_ingress_fwd4(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_host_ingress_fwd4_ctx *stage_ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int
goog_geneve_pre_netdev_ingress_start(struct __ctx_buff *ctx __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_host_ingress_start(void)
{
	return HOOK_ACT_CONTINUE;
}

static __always_inline int goog_geneve_pre_netdev_ingress_fwd4_ipsec(
	struct __ctx_buff *ctx __maybe_unused,
	struct goog_host_ingress_fwd4_ctx_common *stage_ctx_common __maybe_unused)
{
	return HOOK_ACT_CONTINUE;
}

#endif /* ENABLE_GOOGLE_GENEVE */
