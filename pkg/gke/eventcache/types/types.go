package types

import "net/netip"

type Source int

const (
	KubeAPI Source = iota
	TDxDS
)

func (src Source) String() string {
	switch src {
	case KubeAPI:
		return "Kube API"
	case TDxDS:
		return "Traffic Director xDS"
	default:
		panic("Only two values are allowed for the `source` type.")
	}
}

type ServiceID netip.Addr // TODO(b/320930861) To be replaced with namespace + service_name when possible.

func (i ServiceID) String() string {
	return netip.Addr(i).String()
}
