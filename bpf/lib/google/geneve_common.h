#pragma once

#include "lib/google/hooks_common.h"
#include "lib/ipv4.h"

#ifdef ENABLE_GOOGLE_GENEVE

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

# endif /* ENABLE_IPV4 */
#endif /* ENABLE_GOOGLE_GENEVE */
