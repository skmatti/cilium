package mtu

import "github.com/cilium/cilium/pkg/gke/features"

const (
	// googleTunnelOverhead is an approximation for bytes used for tunnel
	// encapsulation. It accounts for:
	//    (Outer ethernet is not accounted against MTU size)
	//    Outer IPv4 header:  20B
	//    Outer UDP header:    8B
	//    Outer GENEVE header: 8B
	//    Maximal size potential GENEVE option header (DSR IPv6 option): 32B
	//                        ---
	//    Total extra bytes:  68B
	// We do not rely on TunnelOverhead as we don't include the orignal Ethernet
	// header, but OSS Cilium does.
	googleTunnelOverhead = 68
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
