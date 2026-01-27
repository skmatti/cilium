#pragma once

#ifdef ENABLE_GOOGLE_GENEVE

// Redefine ctx functions.
# undef ctx_get_tunnel_key
# define ctx_get_tunnel_key google_ctx_get_tunnel_key
# undef ctx_set_tunnel_key
# define ctx_set_tunnel_key google_ctx_set_tunnel_key
# undef ctx_set_tunnel_opt
# define ctx_set_tunnel_opt google_ctx_set_tunnel_opt
/* Override the ctx_set_encap_info function.
 * Because ctx_set_tunnel_key/ctx_set_tunnel_opt may have already
 * been expanded in previous included header files, we also
 * want to replace ctx_set_encap_info function as well.
 */
# define ctx_set_encap_info google_ctx_set_encap_info

# if __ctx_is == __ctx_xdp

#  undef ctx_adjust_hroom
#  define ctx_adjust_hroom google_ctx_adjust_hroom
#  undef ctx_load_bytes
#  define ctx_load_bytes google_ctx_load_bytes

# endif /* __ctx_is == __ctx_xdp */

#endif /* ENABLE_GOOGLE_GENEVE */