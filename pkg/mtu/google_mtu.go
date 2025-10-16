package mtu

import "github.com/cilium/cilium/pkg/gke/features"

const (
	/* googleTunnelOverhead is an approximation for bytes used for tunnel
	 * encapsulation. It accounts for:
	 *    (Outer ethernet is not accounted against MTU size)
	 *    Outer IPv4 header:  20B
	 *    Outer UDP header:    8B
	 *    Outer GENEVE header: 8B
	 *    Maximal size potential GENEVE option header (DSR IPv6 option): 32B
	 *    (Original Ethernet:  14B): not needed by us
	 *                        ---
	 *    Total extra bytes:  82B
	 * We do not rely on TunnelOverhead as we don't include the orignal Ethernet
	 * header, but OSS Cilium does. Technically, we don't need this 14 bytes
	 * headroom. However, in Viper release we counted the inner Ethernet header.
	 * So we still need to count it to avoid potential issues in MTU during upgrade.
	 */
	googleTunnelOverhead = 82
)

func GoogleTunnelOverhead() int {
	fgc := features.GlobalConfig
	overhead := TunnelOverhead

	if fgc.EnableGoogleBPFGeneve {
		overhead = googleTunnelOverhead
	}
	if fgc.GoogleIPSecMode == features.GoogleIPSecModeSoftware {
		overhead += EncryptionIPsecOverhead
	}
	return overhead
}
